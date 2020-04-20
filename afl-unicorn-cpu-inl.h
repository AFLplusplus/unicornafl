/*
   american fuzzy lop++ - unicorn instrumentation
   ----------------------------------------------

   Originally written by Andrew Griffiths <agriffiths@google.com> and
                         Michal Zalewski

   Adapted for afl-unicorn by Dominik Maier <mail@dmnk.co>

   CompareCoverage and NeverZero counters by Andrea Fioraldi
                                  <andreafioraldi@gmail.com>

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of Unicorn 1.0.1. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting libunicorn binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#include <sys/shm.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unicorn.h>
#include "config.h"
#include "types.h"
#include "afl-unicorn-common.h"

/* We use one additional file descriptor to relay "needs translation"
   or "child done" messages between the child and the fork server. */

#define FF16 (0xFFFFFFFFFFFFFFFF)

/**
 * The correct fds for reading and writing pipes
 */

#define _R(pipe) ((pipe)[0])
#define _W(pipe) ((pipe)[1])

/* Function declarations. */

static void        afl_setup(struct uc_struct*);
static inline uc_afl_ret afl_forkserver(CPUArchState*);
static int afl_find_wifsignaled_id(void);

static enum afl_child_ret afl_handle_child_requests(CPUArchState*);
static void afl_request_tsl(struct uc_struct* uc, target_ulong, target_ulong, uint64_t);
static uc_afl_ret afl_request_next(struct uc_struct* uc, bool found_crash);

// static TranslationBlock* tb_find_slow(CPUArchState*, target_ulong, target_ulong, uint64_t);

/* Data structure passed around by the translate handlers: */

struct afl_tsl {

  target_ulong pc;
  target_ulong cs_base;
  uint64_t     flags;

};

/* Current state, as fowarded from forkserver child to parent */

enum afl_child_ret {

  // Persistent 
  AFL_CHILD_NEXT,
  // Crash discovered but still alive in persistent mode
  AFL_CHILD_FOUND_CRASH,
  // Read again, one afl_tsl struct.
  AFL_CHILD_TSL_REQUEST,
  // Child no longer there. Read status code.
  AFL_CHILD_EXITED,

};

static int wifsignaled;

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

/* Set up SHM region and initialize other stuff. */

static void afl_setup(struct uc_struct* uc) {

  char *id_str = getenv(SHM_ENV_VAR);
  char *inst_r = getenv("AFL_INST_RATIO");
 
  // A value we can use to tell AFL our persistent mode found a crash
  wifsignaled = afl_find_wifsignaled_id();

  int shm_id;

  if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    uc->afl_inst_rms = MAP_SIZE * r / 100;

  } else {

    uc->afl_inst_rms = MAP_SIZE;

  }

  if (id_str) {

    shm_id = atoi(id_str);
    uc->afl_area_ptr = shmat(shm_id, NULL, 0);
    uc->afl_prev_loc = 0;
    uc->afl_area_ptr[0] = 1;

    if (uc->afl_area_ptr == (void*)-1) exit(1);
    
  }

  /* Maintain for compatibility */
  if (getenv("AFL_QEMU_COMPCOV")) { uc->afl_compcov_level = 1; }
  if (getenv("AFL_COMPCOV_LEVEL")) {

    uc->afl_compcov_level = atoi(getenv("AFL_COMPCOV_LEVEL"));

  }

}

// Some dirty hack to come up with a valid statuscode that AFL will just accept.

static int afl_find_wifsignaled_id(void) {

  int ret = 0; // A faux status code that AFL will accept as signaled/crashed. 1 on linux.
  while (!(WIFSIGNALED(ret))) ret++;

#if defined(AFL_DEBUG)
  printf("[d] wifsignaled is %d (WIFSIGNALED(x)=%d)\n", ret, WIFSIGNALED(ret));
#endif

  return ret;

}

/* Fork server logic, invoked by calling uc_afl_forkserver_start.
   Roughly follows https://github.com/vanhauser-thc/AFLplusplus/blob/c83e8e1e6255374b085292ba8673efdca7388d76/llvm_mode/afl-llvm-rt.o.c#L130 
   */

static inline uc_afl_ret afl_forkserver(CPUArchState* env) {

  unsigned char tmp[4] = {0};
  pid_t   child_pid;
  enum afl_child_ret child_ret = AFL_CHILD_EXITED;
  bool first_round = true;

  if (!env->uc->afl_area_ptr) return UC_AFL_RET_NO_AFL;

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return UC_AFL_RET_NO_AFL;

  void (*old_sigchld_handler)(int) = signal(SIGCHLD, SIG_DFL);

  while (1) {

    uint32_t was_killed;
    int      status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) return UC_AFL_RET_FINISHED;

    /* If we stopped the child in persistent mode, but there was a race
    condition and afl-fuzz already issued SIGKILL, write off the old
    process. */

    if ((child_ret != AFL_CHILD_EXITED) && was_killed) {
    
#if defined(AFL_DEBUG)
      printf("[d] Child was killed by AFL in the meantime.\n");
#endif

      child_ret = AFL_CHILD_EXITED;
      if (waitpid(child_pid, &status, 0) < 0) {
        perror("[!] Error waiting for child!");
        return UC_AFL_RET_ERROR;
      }

    }

    if (child_ret == AFL_CHILD_EXITED) {

      /* Child dead. Establish new a channel with child to grab translation commands.
        We'll read from _R(afl_child_pipe), child will write to _W(afl_child_pipe). */

      /* close the read fd of previous round. */

      if (_R(env->uc->afl_child_pipe)) {
        close(_R(env->uc->afl_child_pipe));
        close(_W(env->uc->afl_parent_pipe));
      }

      if (pipe(env->uc->afl_child_pipe)) {
        perror("[!] Error creating pipe to child");
        return UC_AFL_RET_ERROR;
      }
      if (pipe(env->uc->afl_parent_pipe)) {
        perror("[!] Error creating pipe to parent");
        close(_R(env->uc->afl_child_pipe));
        close(_W(env->uc->afl_child_pipe));
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
        // FORKSRV_FD is for communication with AFL, we don't need it in the child.
        close(FORKSRV_FD); 
        close(FORKSRV_FD + 1);
        close(_R(env->uc->afl_child_pipe));
        close(_W(env->uc->afl_parent_pipe));
        env->uc->afl_child_request_next = afl_request_next;

        memset(env->uc->afl_area_ptr, 0, MAP_SIZE);
        MEM_BARRIER(); // Make very sure everything has been written to the map at this point

        if (!first_round) {

          // For persistent mode: Clear the map manually after forks.
          memset(env->uc->afl_area_ptr, 0, MAP_SIZE);

        } else {
          // For persistent mode: Clear the map manually after forks.
          //memset(env->uc->afl_area_ptr, 0, MAP_SIZE);

          first_round = false;
        }

        env->uc->afl_prev_loc = 0;
        // Tell AFL we're alive
        env->uc->afl_area_ptr[0] = 1;

        return UC_AFL_RET_CHILD;

      } else { // parent for new child

        /* If we don't close this in parent, we don't get notified on afl_child_pipe once child is gone. */

        close(_W(env->uc->afl_child_pipe));
        close(_R(env->uc->afl_parent_pipe));

      }

    } else { // parent, in persistent mode

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with a write to afl_parent_pipe. */

      if (write(_W(env->uc->afl_parent_pipe), tmp, 4) != 4) {

        fprintf(stderr,"[!] Child died when we tried to resume it\n");
        return UC_AFL_RET_ERROR;

      }

    }

    /* In parent process: write PID to AFL. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
      return UC_AFL_RET_FINISHED;
    }

    /* Collect translation requests until child finishes a run or dies */

    child_ret = afl_handle_child_requests(env);

    if (child_ret == AFL_CHILD_NEXT) {

      /* Child asks for next in persistent mode  */

      status = 0;

    } else if (child_ret == AFL_CHILD_FOUND_CRASH) {

      /* WIFSIGNALED(wifsignaled) == 1 -> tells AFL the child crashed (even though it's still alive for persistent mode) */
      
      status = wifsignaled;

    } else if (child_ret == AFL_CHILD_EXITED) {

      /* If child exited, get and relay exit status to parent through waitpid. */

      if (waitpid(child_pid, &status, 0) < 0) {

        // Zombie Child could not be collected. Scary!
        perror("[!] The child's exit code could not be determined. ");
        return UC_AFL_RET_ERROR;

      }

    }

    /* Relay wait status to AFL pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) return UC_AFL_RET_FINISHED;

  }

}

/* This code is invoked whenever Unicorn decides that it doesn't have a
   translation of a particular block and needs to compute it. When this happens,
   we tell the parent to mirror the operation, so that the next fork() has a
   cached copy. */

static inline void afl_request_tsl(struct uc_struct* uc, target_ulong pc, target_ulong cb, uint64_t flags) {

  /* Dual use: if this func is not set, we're not a child process */

  if (uc->afl_child_request_next == NULL) return;

  enum afl_child_ret tsl_req = AFL_CHILD_TSL_REQUEST;

  struct afl_tsl t = {
    .pc = pc,
    .cs_base = cb,
    .flags = flags,
  };

#if defined(AFL_DEBUG)
  printf("Requesting tsl, pc=0x%lx, cb=0x%lx, flags=0x%lx\n", (uint64_t) pc, (uint64_t) cb, flags);
#endif

  // We write tsl requests in two steps but that's fine since cache requests are not very common over the time of fuzzing.

  if ((write(_W(uc->afl_child_pipe), &tsl_req, sizeof(enum afl_child_ret)) != sizeof(enum afl_child_ret)) 
      || write(_W(uc->afl_child_pipe), &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl)) {

    fprintf(stderr, "Error writing to child pipe. Parent dead?\n");

  }

}

/* This code is invoked whenever the child decides that it is done with one fuzz-case. */

static uc_afl_ret afl_request_next(struct uc_struct* uc, bool crash_found) {

  enum afl_child_ret msg = crash_found? AFL_CHILD_FOUND_CRASH : AFL_CHILD_NEXT;
  unsigned char tmp[4] = {0};

#if defined(AFL_DEBUG)
  printf("[d] request next. crash found: %s\n", crash_found ? "true": "false");
#endif

  MEM_BARRIER(); // Make very sure everything has been written to the map at this point

  if (write(_W(uc->afl_child_pipe), &msg, sizeof(msg)) != sizeof(msg)) {

    fprintf(stderr, "[!] Error writing to parent pipe. Parent dead?\n");
    return UC_AFL_RET_ERROR;

  }

  // Once the parent has written something, the next persistent loop starts.
  // The parent itself will wait for AFL to signal the new testcases is available.
  if (read(_R(uc->afl_parent_pipe), &tmp, 4) != 4) {

    fprintf(stderr, "[!] Error reading from parent pipe. Parent dead?\n");
    return UC_AFL_RET_ERROR;

  }

  memset(uc->afl_area_ptr, 0, MAP_SIZE);
  MEM_BARRIER(); // Also make sure nothing read before this point.

  // Start with a clean slate.
  uc->afl_prev_loc = 0;
  uc->afl_area_ptr[0] = 1;

  return UC_AFL_RET_CHILD;

}


/* This is the reading side of afl_child_pipe. It will handle persistent mode and (tsl) cache requests.
  Since timeouts are handled by afl-fuzz simply killing the child, we can just wait until the pipe breaks.
  For persistent mode, we will also receive child responses over this chanel.
  For persistent mode, if child is still alive, this will return if the child crashed or not */

static enum afl_child_ret afl_handle_child_requests(CPUArchState* env) {

  enum afl_child_ret child_msg;
  struct afl_tsl t;

  while (1) {

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(_R(env->uc->afl_child_pipe), &child_msg, sizeof(enum afl_child_ret)) != sizeof(enum afl_child_ret)) return AFL_CHILD_EXITED; // child is dead.

    if (child_msg == AFL_CHILD_NEXT || child_msg == AFL_CHILD_FOUND_CRASH) {

      // Forward if child found a crash or not, for persistent mode.
      return child_msg;

    } else if (child_msg == AFL_CHILD_TSL_REQUEST) {

      // TODO: Add option to disable cache for self-modifying code? // Ignore code that has not been loaded?

      // Child will send a tsl request next, that we have to cache.
      if (read(_R(env->uc->afl_child_pipe), &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl)) return AFL_CHILD_EXITED; // child is dead.

      // Cache.
      tb_find_slow(env, t.pc, t.cs_base, t.flags);

    } else {
      
      fprintf(stderr, "[!] Unexpected response by child! %d. Please report this as bug for unicornafl.\n"
                      "    Expected one of {AFL_CHILD_NEXT: %d, AFL_CHILD_FOUND_CRASH: %d, AFL_CHILD_TSL_REQUEST: %d}.\n", 
                      child_msg, AFL_CHILD_NEXT, AFL_CHILD_FOUND_CRASH, AFL_CHILD_TSL_REQUEST);

    }

  }

}
