#include "unicornafl.h"
#include "config.h"
#include "priv.h"

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/fcntl.h>

#include <x86intrin.h>

#ifdef AFL_DEBUG
#include <errno.h>
#define ERR(str, ...)                                                          \
    fprintf(stderr, "[pid=%d] " str, getpid() __VA_OPT__(, ) __VA_ARGS__)
#else
#define ERR(...) fprintf(stderr, __VA_ARGS__)
#endif

class UCAFL {

  public:
    UCAFL(uc_engine* uc, const char* input_file,
          uc_afl_cb_place_input_t place_input_callback,
          uc_afl_cb_validate_crash_t validate_crash_callback,
          bool always_validate, uint32_t persistent_iters, void* data)
        : uc_(uc), input_file_(input_file),
          place_input_callback_(place_input_callback),
          validate_crash_callback_(validate_crash_callback),
          always_validate_(always_validate),
          persistent_iters_(persistent_iters), data_(data),
          afl_testcase_ptr_(nullptr), afl_testcase_len_p_(nullptr),
          afl_area_ptr_(nullptr), has_afl_(false), afl_prev_loc_(0), h1_(0),
          h2_(0), h3_(0), h4_(0) {}

    UCAFL(const UCAFL& ucafl) = delete;

    uc_afl_ret set_exits(const uint64_t* exits, size_t exit_count) {
        uc_err err;
        std::vector<uint64_t> v;

        err = uc_ctl_exits_enable(this->uc_);
        if (err) {
            ERR("[!] Fail to enable exits for Unicorn Engine.\n");
            return UC_AFL_RET_ERROR;
        }

        v.assign(exits, exits + exit_count);
        err = uc_ctl_set_exits(uc_, (uint64_t*)&v[0], exit_count);

        if (err) {
            ERR("[!] Fail to set exits.\n");
            return UC_AFL_RET_ERROR;
        }

        return UC_AFL_RET_OK;
    }

    uc_afl_ret fsrv_run() {
        uc_afl_ret ret;
        this->_may_use_shm_testcase();
        this->_afl_steup();
        if (this->has_afl_) {
            this->_uc_setup();
        }

        ret = this->_fksrv_start();

#ifdef AFL_DEBUG
        ERR("[d] fksrv_start returns %d\n", ret);
#endif

        switch (ret) {
        case UC_AFL_RET_CHILD:
            // We are the child.
            return this->_child_fuzz(true);
        case UC_AFL_RET_NO_AFL:
            this->persistent_iters_ = 1;
            // Only run once.
            return this->_child_fuzz(false);
        case UC_AFL_RET_FINISHED:
        case UC_AFL_RET_ERROR:
        case UC_AFL_RET_CALLED_TWICE:
            return ret;
        default:
            return UC_AFL_RET_ERROR;
        }
    }

    ~UCAFL() {
        if (this->h1_) {
            uc_hook_del(this->uc_, this->h1_);
        }

        if (this->h2_) {
            uc_hook_del(this->uc_, this->h2_);
        }

        if (this->h3_) {
            uc_hook_del(this->uc_, this->h3_);
        }

        if (this->h4_) {
            uc_hook_del(this->uc_, this->h4_);
        }

        if(!this->has_afl_) {
            munmap(this->afl_area_ptr_, MAP_SIZE);
        }
    }

  private:
    uc_afl_ret _afl_next(bool crash_found) {

        enum afl_child_ret msg =
            crash_found ? AFL_CHILD_FOUND_CRASH : AFL_CHILD_NEXT;
        char tmp[4];

#if defined(AFL_DEBUG)
        ERR("[d] request next. crash found: %s\n",
            crash_found ? "true" : "false");
#endif

        mem_barrier(); // Make very sure everything has been written to the map
                       // at this point

        if (write(_W(this->afl_child_pipe_), &msg, sizeof(msg)) !=
            sizeof(msg)) {

            ERR("[!] Error writing to parent pipe. Parent dead?\n");
            return UC_AFL_RET_ERROR;
        }

        // Once the parent has written something, the next persistent loop
        // starts. The parent itself will wait for AFL to signal the new
        // testcases is available. This blocks until the next testcase is ready.
        if (read(_R(this->afl_parent_pipe_), tmp, 4) != 4) {

            ERR("[!] Error reading from parent pipe. Parent dead?\n");
            return UC_AFL_RET_ERROR;
        }

        /* For shared map fuzzing, the forkserver parent forwards the size of
         * the current testcase. */
        memset(this->afl_area_ptr_, 0, MAP_SIZE);
        mem_barrier(); // Also make sure nothing read before this point.

        // Start with a clean slate.
        this->afl_prev_loc_ = 0;
        this->afl_area_ptr_[0] = 1;

        return UC_AFL_RET_OK;
    }

    class AFL_TESTCASE {
      public:
        AFL_TESTCASE(UCAFL* ucafl) : ucafl_(ucafl) {
            this->ucafl_->_may_use_mmap_testcase();
        }

        char* ptr() {
            return (char*)this->ucafl_->afl_testcase_ptr_;
        }

        size_t len() {
            return *this->ucafl_->afl_testcase_len_p_;
        }

        ~AFL_TESTCASE() {
            this->ucafl_->_may_unnmap_testcase();
        }

      private:
        UCAFL* ucafl_;
    };

    uint64_t _get_pc() {
        uc_arch arch;
        uc_mode mode;
        uint64_t pc = 0;

        uc_ctl_get_arch(this->uc_, &arch);
        uc_ctl_get_mode(this->uc_, &mode);

        if (arch == UC_ARCH_X86) {
            if (mode == UC_MODE_32) {
                uc_reg_read(this->uc_, UC_X86_REG_EIP, &pc);
            } else if (mode == UC_MODE_16) {
                uc_reg_read(this->uc_, UC_X86_REG_IP, &pc);
            } else {
                uc_reg_read(this->uc_, UC_X86_REG_RIP, &pc);
            }
        } else if (arch == UC_ARCH_ARM) {
            uc_reg_read(this->uc_, UC_ARM_REG_PC, &pc);
        } else if (arch == UC_ARCH_RISCV) {
            uc_reg_read(this->uc_, UC_RISCV_REG_PC, &pc);
        } else if (arch == UC_ARCH_MIPS) {
            uc_reg_read(this->uc_, UC_MIPS_REG_PC, &pc);
        } else if (arch == UC_ARCH_PPC) {
            uc_reg_read(this->uc_, UC_PPC_REG_PC, &pc);
        } else if (arch == UC_ARCH_SPARC) {
            uc_reg_read(this->uc_, UC_SPARC_REG_PC, &pc);
        } else if (arch == UC_ARCH_M68K) {
            uc_reg_read(this->uc_, UC_M68K_REG_PC, &pc);
        }

        return pc;
    }

    uc_afl_ret _child_fuzz(bool afl_exist) {
        bool crash_found = false;
        bool first_round = true;
        bool input_accepted;
        uint32_t i = 0;

#ifdef AFL_DEBUG
        ERR("[d] Entering child fuzzing loop.\n");
#endif

        for (i = 0; this->persistent_iters_ == 0 || i < this->persistent_iters_;
             i++) {
            if (unlikely(first_round)) {
                first_round = false;
            } else {
                if (this->_afl_next(crash_found) != UC_AFL_RET_OK) {
                    exit(1);
                }

                crash_found = false;
            }

            AFL_TESTCASE testcase(this);

            input_accepted = this->place_input_callback_(
                this->uc_, testcase.ptr(), testcase.len(), i, this->data_);

            if (unlikely(!input_accepted)) {
#ifdef AFL_DEBUG
                ERR("[d] Input is not accepted.\n");
#endif
                continue;
            }

            // (Lazymio): maybe we cant get rid of this small overhead in the future?
            uint64_t pc = this->_get_pc();

#ifdef AFL_DEBUG
            ERR("[d] We are starting from 0x%" PRIx64 "\n", pc);
#endif

            // Note we have enabled exits.
            uc_err uc_ret = uc_emu_start(this->uc_, pc, 0, 0, 0);

#ifdef AFL_DEBUG
            ERR("[d] We are stopping for uc_err=%d (%s)\n", uc_ret,
                uc_strerror(uc_ret));
#endif

            if (unlikely(uc_ret != UC_ERR_OK) ||
                (this->always_validate_ && this->validate_crash_callback_)) {

                if (this->validate_crash_callback_ &&
                    !this->validate_crash_callback_(
                        this->uc_, uc_ret, testcase.ptr(), testcase.len(), i,
                        this->data_)) {
                    continue;
                }

                if (this->persistent_iters_ != 1) {
                    crash_found = true;
                    continue;
                }

                ERR("[!] UC returned Error: '%s' - let's abort().\n",
                    uc_strerror(uc_ret));
                fflush(stderr);

                abort();
            }
        }

        // We are still in the child, nothing good will come after this.
        // Exit and let the next generation run.
        if (likely(afl_exist)) {
            exit(0);
        }

        // Just run once.
        return UC_AFL_RET_NO_AFL;
    }

    static void _uc_hook_new_tb(uc_engine* uc, uc_tb* cur_tb, uc_tb* prev_tb,
                                void* user_data) {
        UCAFL* ucafl = (UCAFL*)user_data;
        enum afl_child_ret tsl_req = AFL_CHILD_TSL_REQUEST;

        // TODO: Gen unique id for the edge.
        if ((write(_W(ucafl->afl_child_pipe_), &tsl_req,
                   sizeof(enum afl_child_ret))) != sizeof(enum afl_child_ret) ||
            (write(_W(ucafl->afl_child_pipe_), &cur_tb->pc, 8) != 8)) {
            ERR("[!] Fail to request cache at 0x%" PRIx64 "\n", cur_tb->pc);
        }

#ifdef AFL_DEBUG
        ERR("[d] A new TB is generated at 0x%" PRIx64 "\n", cur_tb->pc);
#endif
    }

    static void _uc_hook_block(uc_engine* uc, uint64_t address, uint32_t size,
                               void* user_data) {
        uint64_t cur_loc = ((address >> 4) ^ (address << 8)) & (MAP_SIZE - 7);
        UCAFL* ucafl = (UCAFL*)user_data;

        ucafl->afl_area_ptr_[cur_loc ^ ucafl->afl_prev_loc_]++;
        ucafl->afl_prev_loc_ = cur_loc >> 1;

#ifdef AFL_DEBUG
        ERR("[d] uc_hook_block cur_loc=" PRIu64 " prev_loc=" PRIu64 "\n",
            cur_loc, ucafl->afl_prev_loc_);
#endif
    }

    void _uc_hook_sub_impl_16(uint64_t cur_loc, uint64_t arg1, uint64_t arg2) {
        if ((arg1 & 0xff00) == (arg2 & 0xff00)) {
            this->afl_area_ptr_[(cur_loc) ^ this->afl_prev_loc_]++;
        }
    }

    void _uc_hook_sub_impl_32(uint64_t cur_loc, uint64_t arg1, uint64_t arg2) {
        if ((arg1 & 0xff000000) == (arg2 & 0xff000000)) {

            this->afl_area_ptr_[(cur_loc + 2) ^ this->afl_prev_loc_]++;
            if ((arg1 & 0xff0000) == (arg2 & 0xff0000)) {

                this->afl_area_ptr_[(cur_loc + 1) ^ this->afl_prev_loc_]++;
                if ((arg1 & 0xff00) == (arg2 & 0xff00)) {
                    this->afl_area_ptr_[(cur_loc) ^ this->afl_prev_loc_]++;
                }
            }
        }
    }

    void _uc_hook_sub_impl_64(uint64_t cur_loc, uint64_t arg1, uint64_t arg2) {
        if ((arg1 & 0xff00000000000000) == (arg2 & 0xff00000000000000)) {

            this->afl_area_ptr_[(cur_loc + 6) ^ this->afl_prev_loc_]++;
            if ((arg1 & 0xff000000000000) == (arg2 & 0xff000000000000)) {

                this->afl_area_ptr_[(cur_loc + 5) ^ this->afl_prev_loc_]++;
                if ((arg1 & 0xff0000000000) == (arg2 & 0xff0000000000)) {

                    this->afl_area_ptr_[(cur_loc + 4) ^ this->afl_prev_loc_]++;
                    if ((arg1 & 0xff00000000) == (arg2 & 0xff00000000)) {

                        this->afl_area_ptr_[(cur_loc + 3) ^
                                            this->afl_prev_loc_]++;
                        if ((arg1 & 0xff000000) == (arg2 & 0xff000000)) {

                            this->afl_area_ptr_[(cur_loc + 2) ^
                                                this->afl_prev_loc_]++;
                            if ((arg1 & 0xff0000) == (arg2 & 0xff0000)) {

                                this->afl_area_ptr_[(cur_loc + 1) ^
                                                    this->afl_prev_loc_]++;
                                if ((arg1 & 0xff00) == (arg2 & 0xff00)) {
                                    this->afl_area_ptr_[(cur_loc) ^
                                                        this->afl_prev_loc_]++;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    void _uc_hook_sub_impl(uint64_t cur_loc, uint64_t arg1, uint64_t arg2,
                           uint32_t size) {
        if (size >= 64) {
            this->_uc_hook_sub_impl_64(cur_loc, arg1, arg2);
        } else if (size >= 32) {
            this->_uc_hook_sub_impl_32(cur_loc, arg1, arg2);
        } else {
            this->_uc_hook_sub_impl_16(cur_loc, arg1, arg2);
        }
    }

    static void _uc_hook_sub_cmp(uc_engine* uc, uint64_t address, uint64_t arg1,
                                 uint64_t arg2, uint32_t size,
                                 void* user_data) {
        UCAFL* ucafl = (UCAFL*)user_data;
        uint64_t cur_loc = ((address >> 4) ^ (address << 8)) & (MAP_SIZE - 7);

        if (unlikely(cur_loc >= ucafl->afl_inst_rms_)) {
            return;
        }

        ucafl->_uc_hook_sub_impl(cur_loc, arg1, arg2, size);
    }

    static void _uc_hook_sub(uc_engine* uc, uint64_t address, uint64_t arg1,
                             uint64_t arg2, uint32_t size, void* user_data) {
        _uc_hook_sub_cmp(uc, address, arg1, arg2, size, user_data);
    }

    void _uc_setup() {
        uc_err err;
        uint32_t ver;

        ver = uc_version(NULL, NULL);

        // We need at least Unicorn 2.0.0rc5
        if (ver < MIN_UC_VERSION) {
            ERR("[!] You Unicorn Version 0x%" PRIx32 " is not supported!\n", ver);
            exit(1);
        }

        // For coverage.
        err = uc_hook_add(this->uc_, &this->h1_, UC_HOOK_BLOCK,
                          (void*)_uc_hook_block, (void*)this, 1, 0);
        if (err) {
            ERR("Failed to setup block hook.\n");
            exit(1);
        }

        // For TB caching.
        err = uc_hook_add(this->uc_, &this->h2_, UC_HOOK_EDGE_GENERATED,
                          (void*)_uc_hook_new_tb, (void*)this, 1, 0);
        if (err) {
            ERR("Failed to setup new edge hook.\n");
            exit(1);
        }

        // These two hooks are for compcov and may not be supported by the arch.
        // err = uc_hook_add(this->uc_, &this->h3_, UC_HOOK_TCG_OPCODE,
        //                   (void*)_uc_hook_sub, (void*)this, 1, 0, UC_TCG_OP_SUB,
        //                   UC_TCG_OP_FLAG_DIRECT);

        // err = uc_hook_add(this->uc_, &this->h4_, UC_HOOK_TCG_OPCODE,
        //                   (void*)_uc_hook_sub_cmp, (void*)this, 1, 0,
        //                   UC_TCG_OP_SUB, UC_TCG_OP_FLAG_CMP);
    }

    void _afl_steup() {
        char* map_id_str = getenv(SHM_ENV_VAR);
        char* inst_r_str = getenv("AFL_INST_RATIO");

        this->_setup_valid_wifsignaled();

        if (inst_r_str) {
            uint32_t r = atol(inst_r_str);

            if (r > 100) {
                r = 100;
            } else if (r == 0) {
                r = 1;
            }

            this->afl_inst_rms_ = MAP_SIZE * r / 100;
        } else {
            this->afl_inst_rms_ = MAP_SIZE;
        }

        if (likely(map_id_str)) {
            int map_id = atoi(map_id_str);

            this->afl_area_ptr_ = (uint8_t*)shmat(map_id, NULL, 0);

            if (this->afl_area_ptr_ == (void*)-1) {
                ERR("[!] Can't get the afl mapping area.\n");
                exit(0);
            }

            this->has_afl_ = true;

            // Don't let our parent give up on us.
            this->afl_area_ptr_[0] = 1;
        } else {
            this->afl_area_ptr_ =
                (uint8_t*)mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

            if (this->afl_area_ptr_ == MAP_FAILED) {
                perror("[!] mmap failed.");
                exit(0);
            }

            this->has_afl_ = false;
        }
    }

    uc_afl_ret _fksrv_start() {
        unsigned char tmp[4] = {0};
        pid_t child_pid;
        enum afl_child_ret child_ret = AFL_CHILD_EXITED;
        bool first_round = true;
        uint32_t status = 0;

        if (!this->has_afl_)
            return UC_AFL_RET_NO_AFL;

        if (this->afl_testcase_ptr_) {
            /* Parent supports testcases via shared map - and the user wants to
             * use it. Tell AFL. */
            status = (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ);
        }

        /* Phone home and tell the parent that we're OK. If parent isn't there,
            assume we're not running in forkserver mode and just execute
           program. */

        if (write(FORKSRV_FD + 1, &status, 4) != 4)
            return UC_AFL_RET_NO_AFL;

        /* afl tells us in an extra message if it accepted this option or not */
        if (this->afl_testcase_ptr_ && getenv(SHM_FUZZ_ENV_VAR)) {
            if (read(FORKSRV_FD, &status, 4) != 4) {
                ERR("[!] AFL parent exited before forkserver was up\n");
                return UC_AFL_RET_ERROR;
            }
            if (status != (FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ)) {
                ERR("[!] Unexpected response from AFL++ on forkserver setup\n");
                return UC_AFL_RET_ERROR;
            }
        } else {
#if defined(AFL_DEBUG)
            ERR("[d] AFL++ sharedmap fuzzing not supported/SHM_FUZZ_ENV_VAR "
                "not set\n");
#endif
        }

        void (*old_sigchld_handler)(int) = signal(SIGCHLD, SIG_DFL);

#if defined(AFL_DEBUG)
        ERR("[d] Entering forkserver loop\n");
#endif

        while (1) {

            uint32_t was_killed;
            int status;

            /* Wait for parent by reading from the pipe. Abort if read fails. */

            // See _uc_afl_next
            if (read(FORKSRV_FD, &was_killed, 4) != 4)
                return UC_AFL_RET_FINISHED;

            /* If we stopped the child in persistent mode, but there was a race
            condition and afl-fuzz already issued SIGKILL, write off the old
            process. */

            if ((child_ret != AFL_CHILD_EXITED) && was_killed) {

#if defined(AFL_DEBUG)
                ERR("[d] Child was killed by AFL in the meantime.\n");
#endif

                child_ret = AFL_CHILD_EXITED;
                if (waitpid(child_pid, &status, 0) < 0) {
                    ERR("[!] Error waiting for child!");
                    return UC_AFL_RET_ERROR;
                }
            }

            if (child_ret == AFL_CHILD_EXITED) {

                /* Child dead. Establish new a channel with child to grab
                   translation commands. We'll read from _R(afl_child_pipe),
                   child will write to _W(afl_child_pipe). */

                /* close the read fd of previous round. */

                if (_R(this->afl_child_pipe_)) {
                    close(_R(this->afl_child_pipe_));
                    close(_W(this->afl_parent_pipe_));
                }

                if (pipe(this->afl_child_pipe_)) {
                    perror("[!] Error creating pipe to child");
                    return UC_AFL_RET_ERROR;
                }
                if (pipe(this->afl_parent_pipe_)) {
                    perror("[!] Error creating pipe to parent");
                    close(_R(this->afl_child_pipe_));
                    close(_W(this->afl_child_pipe_));
                    return UC_AFL_RET_ERROR;
                }

                /* Create a clone of our process. */

                child_pid = fork();
                if (child_pid < 0) {
                    perror("[!] Could not fork! ");
                    return UC_AFL_RET_ERROR;
                }

                /* In child process: close fds, resume execution. */

                if (!child_pid) { // New child

                    signal(SIGCHLD, old_sigchld_handler);
                    // FORKSRV_FD is for communication with AFL, we don't need
                    // it in the child.
                    close(FORKSRV_FD);
                    close(FORKSRV_FD + 1);
                    close(_R(this->afl_child_pipe_));
                    close(_W(this->afl_parent_pipe_));

                    memset(this->afl_area_ptr_, 0, MAP_SIZE);
                    mem_barrier(); // Make very sure everything has been written
                                   // to the map at this point

                    if (!first_round) {

                        // For persistent mode: Clear the map manually after
                        // forks.
                        memset(this->afl_area_ptr_, 0, MAP_SIZE);

                    } else {

                        first_round = false;
                    }

                    this->afl_prev_loc_ = 0;
                    // Tell AFL we're alive
                    this->afl_area_ptr_[0] = 1;

                    return UC_AFL_RET_CHILD;

                } else { // parent for new child

                    /* If we don't close this in parent, we don't get notified
                     * on afl_child_pipe once child is gone. */

                    close(_W(this->afl_child_pipe_));
                    close(_R(this->afl_parent_pipe_));
                }

            } else { // parent, in persistent mode

                /* Special handling for persistent mode: if the child is alive
                   but currently stopped, simply restart it with a write to
                   afl_parent_pipe. In case we fuzz using shared map, use this
                   method to forward the size of the current testcase to the
                   child without cost. */

                // See _uc_afl_next
                if (write(_W(this->afl_parent_pipe_), tmp, 4) != 4) {

                    ERR("[!] Child died when we tried to resume it\n");
                    return UC_AFL_RET_ERROR;
                }
            }

            /* In parent process: write PID to AFL. */

            if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
                return UC_AFL_RET_FINISHED;
            }

            /* Collect translation requests until child finishes a run or dies
             */

            child_ret = this->_handle_child_requests();

            if (child_ret == AFL_CHILD_NEXT) {

                /* Child asks for next in persistent mode  */

                // This status tells AFL we are not crashed.
                status = 0;

            } else if (child_ret == AFL_CHILD_FOUND_CRASH) {

                /* WIFSIGNALED(wifsignaled) == 1 -> tells AFL the child crashed
                 * (even though it's still alive for persistent mode) */

                status = this->wifsignaled_;

            } else if (child_ret == AFL_CHILD_EXITED) {

                /* If child exited, get and relay exit status to parent through
                 * waitpid. */

                if (waitpid(child_pid, &status, 0) < 0) {

                    // Zombie Child could not be collected. Scary!
                    perror(
                        "[!] The child's exit code could not be determined. ");
                    return UC_AFL_RET_ERROR;
                }
            }

            /* Relay wait status to AFL pipe, then loop back. */

            if (write(FORKSRV_FD + 1, &status, 4) != 4)
                return UC_AFL_RET_FINISHED;
        }
    }

    afl_child_ret _handle_child_requests() {
        enum afl_child_ret child_msg;

#ifdef AFL_DEBUG
        ERR("[d] Entering _handle_child_requests\n");
#endif

        while (1) {

            /* Broken pipe means it's time to return to the fork server routine.
             */

            if (read(_R(this->afl_child_pipe_), &child_msg,
                     sizeof(enum afl_child_ret)) != sizeof(enum afl_child_ret))
                return AFL_CHILD_EXITED; // child is dead.

#ifdef AFL_DEBUG
            ERR("[d] Get a child_msg=%d\n", child_msg);
#endif

            if (child_msg == AFL_CHILD_NEXT ||
                child_msg == AFL_CHILD_FOUND_CRASH) {

                // Forward if child found a crash or not, for persistent mode.
                return child_msg;

            } else if (child_msg == AFL_CHILD_TSL_REQUEST) {
                uint64_t pc;
                uc_err err;

                if (read(_R(this->afl_child_pipe_), &pc, 8) != 8) {
                    ERR("[d] Fail to read child tsl request.\n");
                    return AFL_CHILD_EXITED; // child is dead.
                }

                err = uc_ctl_request_cache(this->uc_, pc, NULL);

                if (unlikely(err != UC_ERR_OK)) {
                    ERR("[d] Fail to cache the TB at 0x%" PRIx64 ".\n", pc);
                }

            } else {

                fprintf(
                    stderr,
                    "[!] Unexpected response by child! %d. Please report this "
                    "as bug for unicornafl.\n"
                    "    Expected one of {AFL_CHILD_NEXT: %d, "
                    "AFL_CHILD_FOUND_CRASH: %d, AFL_CHILD_TSL_REQUEST: %d}.\n",
                    child_msg, AFL_CHILD_NEXT, AFL_CHILD_FOUND_CRASH,
                    AFL_CHILD_TSL_REQUEST);
            }
        }
    }

    void _setup_valid_wifsignaled() {
        int ret = 0;

        // Just need a value that greater than 0 to inform AFL we are crashed.
        while (!(WIFSIGNALED(ret))) {
            ret++;
        }

        this->wifsignaled_ = ret;
    }

    void _may_use_shm_testcase() {
        char* id_str = getenv(SHM_FUZZ_ENV_VAR);

        if (id_str) {
            int shm_id = atoi(id_str);
            uint32_t* map = (uint32_t*)shmat(shm_id, NULL, 0);
            if (!map || map == MAP_FAILED) {
                perror("[!] could not access fuzzing shared memory");
                exit(1);
            }

            this->afl_testcase_len_p_ = map;
            this->afl_testcase_ptr_ = map + 1;
            this->afl_use_shm_testcase_ = true;
            return;
        } else {
            this->afl_use_shm_testcase_ = false;
            ERR("[!] SHARED MEMORY FUZZING Feature is not enabled.\n");
            return;
        }
    }

    void _may_unnmap_testcase() {
        if (unlikely(!this->afl_use_shm_testcase_)) {
            munmap(this->afl_testcase_ptr_, this->afl_testcase_len_);
        }
    }

    void _may_use_mmap_testcase() {
        off_t ret;
        struct stat st = {0};

        if (unlikely(!this->afl_use_shm_testcase_)) {
            this->afl_testcase_len_p_ = &this->afl_testcase_len_;
            int fd = open(this->input_file_, O_RDONLY);

            if (fstat(fd, &st)) {
                perror("[!] Fail to stat.");
                exit(1);
            }

            this->afl_testcase_ptr_ = (uint32_t*)mmap(
                NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

            if (this->afl_testcase_ptr_ == MAP_FAILED) {
                perror("[!] Fail to mmap testcase.");
                exit(1);
            }

            this->afl_testcase_len_ = (uint32_t)st.st_size;

            close(fd);
        }
    }

  private:
    uc_engine* uc_;
    const char* input_file_;
    uc_afl_cb_place_input_t place_input_callback_;
    uc_afl_cb_validate_crash_t validate_crash_callback_;
    bool always_validate_;
    uint32_t persistent_iters_;
    void* data_;
    // Used both in shm and mmap testcase
    uint32_t* afl_testcase_ptr_;
    uint32_t* afl_testcase_len_p_;
    bool afl_use_shm_testcase_;
    // Only used in mmap testcase.
    uint32_t afl_testcase_len_;
    // Core mapping for coverage
    uint8_t* afl_area_ptr_;
    // This variable checks whether we get a mapping from AFL.
    bool has_afl_;
    uint32_t afl_inst_rms_;
    uint64_t afl_prev_loc_;

    // Fake signal value
    int wifsignaled_;

    // Communication pipe
    int afl_child_pipe_[2];
    int afl_parent_pipe_[2];

    // Our hooks
    uc_hook h1_;
    uc_hook h2_;
    uc_hook h3_;
    uc_hook h4_;
};

extern "C" UNICORNAFL_EXPORT uc_afl_ret uc_afl_fuzz(
    uc_engine* uc, char* input_file,
    uc_afl_cb_place_input_t place_input_callback, uint64_t* exits,
    size_t exit_count, uc_afl_cb_validate_crash_t validate_crash_callback,
    bool always_validate, uint32_t persistent_iters, void* data) {
#ifdef AFL_DEBUG
    ERR("[d] Entering uc_afl_fuzz with input_file=%s and "
        "persistent_iters=%" PRIu32 "\n",
        input_file, persistent_iters);
#endif
    // Sanity Check.
    if (!uc) {
        ERR("[!] Unicorn Engine passed to uc_afl_fuzz is NULL!\n");
        return UC_AFL_RET_ERROR;
    }
    if (!input_file || input_file[0] == 0) {
        ERR("[!] No input file provided to uc_afl_fuzz.\n");
        return UC_AFL_RET_ERROR;
    }
    if (!place_input_callback) {
        ERR("[!] no place_input_callback set.\n");
        return UC_AFL_RET_ERROR;
    }
    if (always_validate && !validate_crash_callback) {
        ERR("[!] always_validate set but validate_crash_callback is "
            "missing.\n");
        return UC_AFL_RET_ERROR;
    }
    if (!exit_count) {
        ERR("[!] Nullptr provided for exits.\n");
        return UC_AFL_RET_ERROR;
    }

    UCAFL ucafl(uc, input_file, place_input_callback, validate_crash_callback,
                always_validate, persistent_iters, data);

    if (unlikely(ucafl.set_exits(exits, exit_count))) {
        return UC_AFL_RET_ERROR;
    }

    return ucafl.fsrv_run();
}