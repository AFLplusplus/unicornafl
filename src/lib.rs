use std::{
    ffi::c_uchar,
    os::raw::{c_char, c_void},
};

use target::child_fuzz;
use unicorn_engine::{ffi::uc_handle, uc_error};

pub mod executor;
pub mod harness;
pub mod hash;
pub mod target;

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum uc_afl_ret {
    UC_AFL_RET_OK = 0,
    UC_AFL_RET_ERROR,
    UC_AFL_RET_CHILD,
    UC_AFL_RET_NO_AFL,
    UC_AFL_RET_CALLED_TWICE,
    UC_AFL_RET_FINISHED,
    UC_AFL_RET_INVALID_UC,
    UC_AFL_RET_UC_ERR,
    UC_AFL_RET_LIBAFL,
}

impl From<libafl::Error> for uc_afl_ret {
    fn from(_: libafl::Error) -> Self {
        Self::UC_AFL_RET_LIBAFL
    }
}

impl From<uc_error> for uc_afl_ret {
    fn from(_: uc_error) -> Self {
        Self::UC_AFL_RET_UC_ERR
    }
}

#[allow(non_camel_case_types)]
pub type uc_afl_cb_place_input_t = extern "C" fn(
    uc: uc_handle,
    input: *const c_uchar,
    input_len: usize,
    persistent_round: u64,
    data: *mut c_void,
) -> bool;

#[allow(non_camel_case_types)]
pub type uc_afl_cb_validate_crash_t = extern "C" fn(
    uc: uc_handle,
    unicorn_result: uc_error,
    input: *const c_uchar,
    input_len: usize,
    persistent_round: u64,
    data: *mut c_void,
) -> bool;

#[allow(non_camel_case_types)]
pub type uc_afl_fuzz_cb_t = extern "C" fn(uc: uc_handle, data: *mut c_void) -> uc_error;

#[no_mangle]
#[allow(non_camel_case_types)]
pub extern "C" fn uc_afl_fuzz(
    uc: uc_handle,
    input_file: *mut c_char,
    place_input_callback: uc_afl_cb_place_input_t,
    exits: *mut u64,
    exit_count: usize,
    validate_crash_callback: Option<uc_afl_cb_validate_crash_t>,
    always_validate: bool,
    persistent_iters: u32,
    data: *mut c_void,
) -> uc_afl_ret {
    if !input_file.is_null() {
        eprintln!("Input file (or @@) is no longer needed for unicornafl v3.0");
    }

    match child_fuzz(
        uc,
        persistent_iters,
        place_input_callback,
        validate_crash_callback,
        if exits.is_null() {
            vec![]
        } else {
            unsafe { std::slice::from_raw_parts(exits, exit_count) }.to_vec()
        },
        None,
        always_validate,
        true,
        data,
    ) {
        Ok(_) => uc_afl_ret::UC_AFL_RET_OK,
        Err(e) => e,
    }
}

#[no_mangle]
#[allow(non_camel_case_types)]
pub extern "C" fn uc_afl_fuzz_custom(
    uc: uc_handle,
    input_file: *mut c_char,
    place_input_callback: uc_afl_cb_place_input_t,
    fuzz_callback: uc_afl_fuzz_cb_t,
    validate_crash_callback: Option<uc_afl_cb_validate_crash_t>,
    always_validate: bool,
    persistent_iters: u32,
    data: *mut c_void,
) -> uc_afl_ret {
    if !input_file.is_null() {
        eprintln!("Input file (or @@) is no longer needed for unicornafl v3.0");
    }
    match child_fuzz(
        uc,
        persistent_iters,
        place_input_callback,
        validate_crash_callback,
        vec![],
        Some(fuzz_callback),
        always_validate,
        true,
        data,
    ) {
        Ok(_) => uc_afl_ret::UC_AFL_RET_OK,
        Err(e) => e,
    }
}
