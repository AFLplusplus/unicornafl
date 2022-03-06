#ifndef UNICORNAFL_H
#define UNICORNAFL_H

#include "unicorn/unicorn.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __GNUC__
#define UNICORNAFL_EXPORT __attribute__((visibility("default")))
#else
#define UNICORNAFL_EXPORT
#endif

#define MIN_UC_VERSION 0x02000006

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

typedef uc_err (*uc_afl_fuzz_cb_t)(uc_engine *uc, void *data);

//
//  Start our fuzzer.
//
//  If no afl-fuzz instance is found, this function is almost identical to uc_emu_start()
//  
//  @uc: The uc_engine return-ed from uc_open().
//  @input_file: This usually is the input file name provided by the command argument.
//  @place_input_callback: This callback is triggered every time a new child is generated. It returns 
//                         true if the input is accepted, or the input would be skipped.
//  @exits: All possible exits.
//  @exit_count: The count of the @exits array.
//  @validate_crash_callback: This callback is triggered every time to check if we are crashed.                     
//  @always_validate: If this is set to False, validate_crash_callback will be only triggered if
//                    uc_emu_start (which is called internally by uc_afl_fuzz) returns an error. Or
//                    the validate_crash_callback will be triggered every time.
//  @persistent_iters: Fuzz how many times before forking a new child.
//  @data: The extra data user provides.
//
//  @uc_afl_ret: The error the fuzzer returns.
UNICORNAFL_EXPORT
uc_afl_ret uc_afl_fuzz(uc_engine* uc, char* input_file,
                       uc_afl_cb_place_input_t place_input_callback,
                       uint64_t* exits, size_t exit_count,
                       uc_afl_cb_validate_crash_t validate_crash_callback,
                       bool always_validate, uint32_t persistent_iters,
                       void* data);

//
// By default, uc_afl_fuzz internall calls uc_emu_start only once and if uc_emu_stop
// is called, the child will stop fuzzing current test case.
//
// To implement more complex fuzzing logic, pass an extra fuzzing_callback with this API.
//
UNICORN_EXPORT
uc_afl_ret uc_afl_fuzz_custom(uc_engine* uc, char* input_file,
                              uc_afl_cb_place_input_t place_input_callback,
                              uc_afl_fuzz_cb_t fuzz_callbck,
                              uc_afl_cb_validate_crash_t validate_crash_callback,
                              bool always_validate, uint32_t persistent_iters,
                              void* data);

#ifdef __cplusplus
}
#endif

#endif