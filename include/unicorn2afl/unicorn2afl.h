#ifndef UNICORN2AFL_H
#define UNICORN2AFL_H

#include "unicorn/unicorn.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __GNUC__
#define UNICORN2AFL_EXPORT __attribute__((visibility("default")))
#else
#define UNICORN2AFL_EXPORT
#endif

#define MIN_UC_VERSION 0x02000005

typedef enum uc_afl_ret {
    UC_AFL_RET_OK = 0,
    UC_AFL_RET_ERROR,
    UC_AFL_RET_CHILD,
    UC_AFL_RET_NO_AFL,
    UC_AFL_RET_CALLED_TWICE,
    UC_AFL_RET_FINISHED,
} uc_afl_ret;

typedef bool (*uc_afl_cb_place_input_t)(uc_engine* uc, char* input,
                                        size_t input_len,
                                        uint32_t persistent_round, void* data);

typedef bool (*uc_afl_cb_validate_crash_t)(uc_engine* uc, uc_err unicorn_result,
                                           char* input, int input_len,
                                           int persistent_round, void* data);

UNICORN2AFL_EXPORT
uc_afl_ret uc_afl_fuzz(uc_engine* uc, char* input_file,
                       uc_afl_cb_place_input_t place_input_callback,
                       uint64_t* exits, size_t exit_count,
                       uc_afl_cb_validate_crash_t validate_crash_callback,
                       bool always_validate, uint32_t persistent_iters,
                       void* data);

#ifdef __cplusplus
}
#endif

#endif