#if defined(UNICORN_AFL)

#if defined(UNICORN_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#endif

#include <string.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/shm.h>

#include "config.h"
#include "types.h"
#include "uc_priv.h"

UNICORN_EXPORT
uc_afl_ret uc_afl_forkserver_start(uc_engine *uc, uint64_t *exits, size_t exit_count)
{
    /*
    Why we need exits as parameter to forkserver:
    In the original unicorn-afl, Unicorn needed to flush the tb cache for every iteration.
    This is super slow.
    Problem was, that the original forked server doesn't know about possible future exits.
    The cached blocks, in the next child, therefore would have no exit set and run forever.
    Also it's nice to have multiple exits, so let's just do it right.
    */

    if (!uc) {
        fprintf(stderr, "[!] Unicorn Engine passed to uc_afl_fuzz is NULL!\n");
        return UC_AFL_RET_ERROR;
    }
    if (!exit_count) {
        fprintf(stderr, "[!] Nullptr provided for exits.\n");
        return UC_AFL_RET_ERROR;
    }
    if (unlikely(uc->afl_area_ptr)) {
#if defined(AFL_DEBUG)
        fprintf(stderr, "[!] forkserver_start(...) called twice. Already fuzzing!\n");
#endif
        return UC_AFL_RET_CALLED_TWICE; // AFL has already been started before.
    }

    /* Copy exits to unicorn env buffer */
    uc->exits = g_realloc(uc->exits, sizeof(exits[0]) * exit_count);
    if (uc->exits == NULL) {
        perror("[!] malloc failed when starting forkserver.");
        return UC_AFL_RET_ERROR;
    }
    memcpy(uc->exits, exits, sizeof(exits[0]) * exit_count);
    uc->exit_count = exit_count;

    /* Fork() :) */
    return uc->afl_forkserver_start(uc);

}

/* AFL++ supports testcase forwarding via shared map.
   If the env variable is set, get the shared map here.
   returns true if we enabled shmap fuzzing, false otherwise. */
static bool uc_afl_enable_shm_testcases(uc_engine *uc) {

    char *id_str = getenv(SHM_FUZZ_ENV_VAR);
    if (id_str) {
        int shm_id = atoi(id_str);
        char *map = (char *)shmat(shm_id, NULL, 0);
        if (!map || map == (void *)-1) {
            perror("[!] could not access fuzzing shared memory");
            exit(1);
        }
        uc->afl_testcase_size_p = (u32 *)map;
        uc->afl_testcase_ptr = (map + sizeof(u32));
#if defined(AFL_DEBUG)
        printf("[d] successfully opened shared memory for testcases with id %d\n", shm_id);
#endif
        return true;

    } else {
#if defined(AFL_DEBUG)
        printf("[d] SHM_FUZZ_ENV_VAR not set - not using shared map fuzzing.\n");
#endif
        return false;
    }

}

/* returns the filesize in bytes, -1 or error. */
static inline off_t uc_afl_mmap_file(char *filename, char **buf_ptr) {

    off_t ret = -1;

    int fd = open(filename, O_RDONLY);

    struct stat st = {0};
    if (fstat(fd, &st)) goto exit;

    off_t in_len = st.st_size;

    *buf_ptr = mmap(0, in_len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if (*buf_ptr != MAP_FAILED) ret = in_len;

exit:
    close(fd);
    return ret;

}

/* A start with "less features" for our afl use-case */
/* this is largely copied from uc_emu_start, just without setting the entry point, counter and timeout. */
UNICORN_EXPORT
int uc_afl_emu_start(uc_engine *uc) {

    uc->emu_counter = 0;
    uc->invalid_error = UC_ERR_OK;
    uc->block_full = false;
    uc->emulation_done = false;
    uc->stop_request = false;

    // remove count hook if counting isn't necessary
    if (uc->count_hook != 0) {
        uc_hook_del(uc, uc->count_hook);
        uc->count_hook = 0;
    }

    if (uc->vm_start(uc)) {
        return UC_ERR_RESOURCE;
    }

    // emulation is done
    uc->emulation_done = true;

    return uc->invalid_error;

}

/* afl_next that expects you know what you're doing
   Specifically, it won't check for afl_area_ptr and next to be set. */
static inline uc_afl_ret uc_afl_next_inl(uc_engine *uc, bool crash_found)
{
    // Tell the parent we need a new testcase, then stop until testcase is available.
    if (uc->afl_child_request_next(uc, crash_found) == UC_AFL_RET_ERROR) return UC_AFL_RET_ERROR;
    return UC_AFL_RET_CHILD;

}


/* similar to __afl_persistent loop */
UNICORN_EXPORT
uc_afl_ret uc_afl_next(uc_engine *uc, bool crash_found)
{

    if (unlikely(!uc->afl_area_ptr)) {
        fprintf(stderr, "[!] uc_afl_next(...) called before forkserver_start(...).");
        return UC_AFL_RET_ERROR;
    }

    // Tell the parent we need a new testcase, then stop until testcase is available.
    if (uc->afl_child_request_next) {

        return uc_afl_next_inl(uc, crash_found);

    }

    return UC_AFL_RET_NO_AFL;

}

UNICORN_EXPORT
uc_afl_ret uc_afl_fuzz(
        uc_engine *uc,
        char* input_file,
        uc_afl_cb_place_input_t place_input_callback,
        uint64_t *exits,
        size_t exit_count,
        uc_afl_cb_validate_crash_t validate_crash_callback,
        bool always_validate,
        uint32_t persistent_iters,
        void *data
){

    if (!uc) {
        fprintf(stderr, "[!] Unicorn Engine passed to uc_afl_fuzz is NULL!\n");
        return UC_AFL_RET_ERROR;
    }
    if (!input_file || input_file[0] == 0) {
        fprintf(stderr, "[!] No input file provided to uc_afl_fuzz.\n");
        return UC_AFL_RET_ERROR;
    }
    if (!place_input_callback) {
        fprintf(stderr, "[!] no place_input_callback set.\n");
        return UC_AFL_RET_ERROR;
    }
    if (always_validate && !validate_crash_callback) {
        fprintf(stderr, "[!] always_validate set but validate_crash_callback is missing.\n");
        return UC_AFL_RET_ERROR;
    }
    if (!exit_count) {
        fprintf(stderr, "[!] Nullptr provided for exits.\n");
        return UC_AFL_RET_ERROR;
    }

    uint32_t mmap_in_len = 0;
    char *in_buf = NULL;
    uint32_t *in_len_p = NULL;

    bool use_shmap_input = uc_afl_enable_shm_testcases(uc);
    if (use_shmap_input) {
        /* For shared map fuzzing, the ptr stays the same */
        in_buf = uc->afl_testcase_ptr;
        in_len_p = uc->afl_testcase_size_p;
    } else {
        in_len_p = &mmap_in_len;
    }

    uc_afl_ret afl_ret = uc_afl_forkserver_start(uc, exits, exit_count);
    switch(afl_ret) {
        case UC_AFL_RET_CHILD:
            break;
        case UC_AFL_RET_NO_AFL:
            // Not running in AFL.
            persistent_iters = 1;
            break;
        case UC_AFL_RET_FINISHED:
            // Nothing more to do
            return afl_ret;
        case UC_AFL_RET_ERROR:
        case UC_AFL_RET_CALLED_TWICE:
            // Nothing more we can do
            return afl_ret;
        default:
            // What have we done
            fprintf(stderr, "[!] Unexpected forkserver return: %d", afl_ret);
            return UC_AFL_RET_ERROR;
    }

    bool first_round = true;
    bool crash_found = false;

#if defined(AFL_DEBUG)
    if (uc->afl_testcase_ptr) {
        printf("[d] uc->afl_testcase_ptr = %p, len = %d\n", uc->afl_testcase_ptr, *uc->afl_testcase_size_p);
    }
#endif

    // 0 means never stop child in persistence mode.
    uint32_t i;
    for (i = 0; persistent_iters == 0 || i < persistent_iters; i++) {

        // The main fuzz loop starts here :)
        if (first_round) {
            first_round = false;
        } else {
            if (uc_afl_next_inl(uc, crash_found) == UC_AFL_RET_ERROR) {
                /* parent is probably gone */
                exit(1);
            }
            crash_found = false;
        }

        /* get input, call place input callback, emulate, unmap input (if needed) */
        if (unlikely(!use_shmap_input)) {
            /* in_buf and the len are not in a shared map (as it would be for sharedmem fuzzing
               No shmap fuzzing involved - Let's read a "normal" file. */
            off_t in_len = uc_afl_mmap_file(input_file, &in_buf);
            if (unlikely(in_len < 0)) {
                fprintf(stderr, "[!] Unable to mmap file: %s (return was %ld)\n", input_file, (long int) in_len);
                perror("mmap");
                fflush(stderr);
                return UC_AFL_RET_ERROR;
            }
            mmap_in_len = in_len;
        }
        bool input_accepted = place_input_callback(uc, in_buf, *in_len_p, i, data);

        if (unlikely(!input_accepted)) {
            // Apparently the input was not to the users' liking. Let's continue.
            goto next_iter;
        }

        uc_err uc_emu_ret = uc_afl_emu_start(uc);

        if (unlikely((uc_emu_ret != UC_ERR_OK) || (always_validate && validate_crash_callback))) {

            if (validate_crash_callback != NULL && validate_crash_callback(
                    uc, uc_emu_ret, in_buf, *in_len_p, i, data) != true) {
                // The callback thinks this is not a valid crash. Ignore.
                goto next_iter;
            }
            if (persistent_iters != 1) {
                // We're inpersistent mode and can report the crash via afl_next. No reason to die.
                crash_found = true;
                goto next_iter;
            }

            fprintf(stderr, "[!] UC returned Error: '%s' - let's abort().\n", uc_strerror(uc_emu_ret));
            fflush(stderr);

            abort();

        }
next_iter:
        if (!use_shmap_input) munmap(in_buf, mmap_in_len);
    }
    // UC_AFL_RET_CHILD -> We looped through all iters.
    // We are still in the child, nothing good will come after this.
    // Exit and let the next generation run.
    if (likely(afl_ret == UC_AFL_RET_CHILD)) {
        exit(0);
    }

    if (uc->afl_area_ptr) {
        // Nothing should ever come after this but clean it up still.
        // shmdt(uc->afl_area_ptr);
        uc->afl_area_ptr = NULL;
        uc->afl_testcase_ptr = NULL;

    }

    // UC_AFL_RET_NO_AFL -> Not fuzzing. We ran once.
    return UC_AFL_RET_NO_AFL;
}

#endif /* UNICORN_AFL */
