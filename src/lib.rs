use std::{
    ffi::{c_uchar, CStr},
    os::raw::{c_char, c_void},
    path::PathBuf,
};

use executor::{UnicornAflExecutorCustomHook, UnicornAflExecutorHook, UnicornFuzzData};
use unicorn_engine::{uc_error, unicorn_const::uc_engine, Unicorn};

pub mod executor;
mod forkserver;
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
    UC_AFL_RET_FFI,
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
    uc: *mut uc_engine,
    input: *const c_uchar,
    input_len: usize,
    persistent_round: u64,
    data: *mut c_void,
) -> bool;

#[allow(non_camel_case_types)]
pub type uc_afl_cb_validate_crash_t = extern "C" fn(
    uc: *mut uc_engine,
    unicorn_result: uc_error,
    input: *const c_uchar,
    input_len: usize,
    persistent_round: u64,
    data: *mut c_void,
) -> bool;

#[allow(non_camel_case_types)]
pub type uc_afl_fuzz_cb_t = extern "C" fn(uc: *mut uc_engine, data: *mut c_void) -> uc_error;

/// Customized afl fuzz routine entrypoint for Rust user.
///
/// `exits` means instruction addresses that stop the execution. You can pass
/// an empty vec here if there is not explicit exit.
///
/// If `always_validate` is true, then `validate_crash_cb` is invoked everytime
/// regardless of the result of execution; Otherwise, only failed execution will
/// invoke such callback.
///
/// `persistent_iters` is the number of persistent execution rounds.
pub fn afl_fuzz_custom<'a, D: 'a>(
    uc: Unicorn<'a, UnicornFuzzData<D>>,
    input_file: Option<PathBuf>,
    callbacks: impl UnicornAflExecutorHook<'a, D>,
    exits: Vec<u64>,
    always_validate: bool,
    persistent_iters: u32,
) -> Result<(), uc_afl_ret> {
    target::child_fuzz(
        uc,
        input_file,
        persistent_iters,
        callbacks,
        exits,
        always_validate,
        true,
    )
}

/// Simplified afl fuzz routine entrypoint for Rust user.
///
/// If you want to manually validate crash or kick fuzzing, call [`afl_fuzz_custom`].
pub fn afl_fuzz<'a, D: 'a>(
    uc: Unicorn<'a, UnicornFuzzData<D>>,
    input_file: Option<PathBuf>,
    place_input_cb: impl FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>, &[u8], u64) -> bool + 'a,
    exits: Vec<u64>,
    always_validate: bool,
    persistent_iters: u32,
) -> Result<(), uc_afl_ret> {
    afl_fuzz_custom(
        uc,
        input_file,
        UnicornAflExecutorCustomHook::new(
            place_input_cb,
            target::dummy_uc_validate_crash_callback,
            target::dummy_uc_fuzz_callback,
        ),
        exits,
        always_validate,
        persistent_iters,
    )
}

/// Fuzzing entrypoint for FFI
#[no_mangle]
#[allow(non_camel_case_types)]
pub extern "C" fn uc_afl_fuzz(
    uc_handle: *mut uc_engine,
    input_file: *const c_char,
    place_input_callback: uc_afl_cb_place_input_t,
    exits: *const u64,
    exit_count: usize,
    validate_crash_callback: Option<uc_afl_cb_validate_crash_t>,
    always_validate: bool,
    persistent_iters: u32,
    data: *mut c_void,
) -> uc_afl_ret {
    uc_afl_fuzz_internal(
        uc_handle,
        input_file,
        place_input_callback,
        exits,
        exit_count,
        None,
        validate_crash_callback,
        always_validate,
        persistent_iters,
        data,
    )
}

/// Custom fuzzing entrypoint for FFI
#[no_mangle]
#[allow(non_camel_case_types)]
pub extern "C" fn uc_afl_fuzz_custom(
    uc_handle: *mut uc_engine,
    input_file: *const c_char,
    place_input_callback: uc_afl_cb_place_input_t,
    fuzz_callback: uc_afl_fuzz_cb_t,
    validate_crash_callback: Option<uc_afl_cb_validate_crash_t>,
    always_validate: bool,
    persistent_iters: u32,
    data: *mut c_void,
) -> uc_afl_ret {
    uc_afl_fuzz_internal(
        uc_handle,
        input_file,
        place_input_callback,
        std::ptr::null(),
        0,
        Some(fuzz_callback),
        validate_crash_callback,
        always_validate,
        persistent_iters,
        data,
    )
}

// In the implementation, there is a lot of manually created closures.
// This is due to the fact that two closure have different types even if
// their signature is the same. As a result, we must split the invocation
// to avoid checking the emptyness inside every round.
#[expect(clippy::too_many_arguments)]
fn uc_afl_fuzz_internal(
    uc_handle: *mut uc_engine,
    input_file: *const c_char,
    place_input_callback: uc_afl_cb_place_input_t,
    exits: *const u64,
    exit_count: usize,
    fuzz_callback: Option<uc_afl_fuzz_cb_t>,
    validate_crash_callback: Option<uc_afl_cb_validate_crash_t>,
    always_validate: bool,
    persistent_iters: u32,
    data: *mut c_void,
) -> uc_afl_ret {
    let fuzz_data = UnicornFuzzData::new(data);
    let uc = match unsafe { Unicorn::from_handle_with_data(uc_handle, fuzz_data) } {
        Ok(uc) => uc,
        Err(err) => {
            return err.into();
        }
    };

    let place_input_cb = move |uc: &mut Unicorn<'_, UnicornFuzzData<*mut c_void>>,
                               input: &[u8],
                               persistent_round: u64| {
        let handle = uc.get_handle();
        let data = uc.get_data_mut().user_data;
        (place_input_callback)(handle, input.as_ptr(), input.len(), persistent_round, data)
    };
    let validate_crash_cb = validate_crash_callback.map(|validate_crash_callback| {
        move |uc: &mut Unicorn<'_, UnicornFuzzData<*mut c_void>>,
              unicorn_result: Result<(), uc_error>,
              input: &[u8],
              persistent_round: u64| {
            let handle = uc.get_handle();
            let data = uc.get_data_mut().user_data;
            let unicorn_result = if let Err(err) = unicorn_result {
                err
            } else {
                uc_error::OK
            };
            (validate_crash_callback)(
                handle,
                unicorn_result,
                input.as_ptr(),
                input.len(),
                persistent_round,
                data,
            )
        }
    });
    let fuzz_cb = fuzz_callback.map(|fuzz_callback| {
        move |uc: &mut Unicorn<'_, UnicornFuzzData<*mut c_void>>| {
            let handle = uc.get_handle();
            let data = uc.get_data_mut().user_data;
            let unicorn_result = fuzz_callback(handle, data);
            if unicorn_result == uc_error::OK {
                Ok(())
            } else {
                Err(unicorn_result)
            }
        }
    });

    let input_file = if input_file.is_null() {
        None
    } else {
        // legacy usage
        let Ok(input_file_str) = unsafe { CStr::from_ptr(input_file) }.to_str() else {
            return uc_afl_ret::UC_AFL_RET_FFI;
        };
        Some(PathBuf::from(input_file_str))
    };

    let exits = if exits.is_null() {
        vec![]
    } else {
        unsafe { std::slice::from_raw_parts(exits, exit_count) }.to_vec()
    };

    let res = match (validate_crash_cb, fuzz_cb) {
        (Some(validate_crash_cb), Some(fuzz_cb)) => afl_fuzz_custom(
            uc,
            input_file,
            UnicornAflExecutorCustomHook::new(place_input_cb, validate_crash_cb, fuzz_cb),
            exits,
            always_validate,
            persistent_iters,
        ),
        (Some(validate_crash_cb), None) => afl_fuzz_custom(
            uc,
            input_file,
            UnicornAflExecutorCustomHook::new(
                place_input_cb,
                validate_crash_cb,
                target::dummy_uc_fuzz_callback,
            ),
            exits,
            always_validate,
            persistent_iters,
        ),
        (None, Some(fuzz_cb)) => afl_fuzz_custom(
            uc,
            input_file,
            UnicornAflExecutorCustomHook::new(
                place_input_cb,
                target::dummy_uc_validate_crash_callback,
                fuzz_cb,
            ),
            exits,
            always_validate,
            persistent_iters,
        ),
        (None, None) => afl_fuzz_custom(
            uc,
            input_file,
            UnicornAflExecutorCustomHook::new(
                place_input_cb,
                target::dummy_uc_validate_crash_callback,
                target::dummy_uc_fuzz_callback,
            ),
            exits,
            always_validate,
            persistent_iters,
        ),
    };

    match res {
        Ok(_) => uc_afl_ret::UC_AFL_RET_OK,
        Err(err) => err,
    }
}
