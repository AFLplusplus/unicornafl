#ifndef UC2AFL_PRIV_H
#define UC2AFL_PRIV_H

#ifndef likely
#if __GNUC__ < 3
#define __builtin_expect(x, n) (x)
#endif

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define mem_barrier() __asm__ volatile("" ::: "memory")

/* We use one additional file descriptor to relay "needs translation"
   or "child done" messages between the child and the fork server. */

#define FF16 (0xFFFFFFFFFFFFFFFF)

/* Copied from aflpp/types.h to talk to forkserver */
#define FS_OPT_ENABLED 0x80000001
#define FS_OPT_SHDMEM_FUZZ 0x01000000

/**
 * The correct fds for reading and writing pipes
 */

#define _R(pipe) ((pipe)[0])
#define _W(pipe) ((pipe)[1])

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

#endif