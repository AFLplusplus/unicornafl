//! Bindings for `unicornafl`
//!

use core::marker::PhantomData;

use alloc::{boxed::Box, vec::Vec};
use libc::{c_int, c_void};

use crate::{ffi::uc_handle, uc_error, Unicorn};

/// FFI for the forkserver
extern "C" {
    fn uc_afl_forkserver_start(
        engine: uc_handle,
        exits: *const u64,
        exit_count: libc::size_t,
    ) -> AflRet;
    fn uc_afl_fuzz(
        engine: uc_handle,
        input_file: *const i8,
        place_input_callback: *mut c_void,
        exits: *const u64,
        exit_count: libc::size_t,
        validate_crash_callback: *mut c_void,
        always_validate: bool,
        persistent_iters: u32,
        data: *mut c_void,
    ) -> AflRet;
}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum AflRet {
    Error = 0,
    Child = 1,
    NoAfl = 2,
    Finished = 3,
}

/// Callback structure we use to call handler functions
struct AflFuzzCallback<'a, 'afl, D: 'a, F: 'a, G: 'a>
where
    F: 'afl + FnMut(&mut Unicorn<'a, D>, &mut [u8], i32) -> bool,
    G: 'afl + FnMut(&mut Unicorn<'a, D>, uc_error, &[u8], i32) -> bool,
{
    pub uc: Unicorn<'a, D>,
    pub input_callback: F,
    pub validate_callback: G,
    pub phantom: PhantomData<&'afl ()>,
}

unsafe extern "C" fn input_placement_callback_proxy<'a, 'afl, D, F, G>(
    uc: uc_handle,
    input: *mut u8,
    input_len: c_int,
    persistent_round: c_int,
    user_data: *mut AflFuzzCallback<'a, 'afl, D, F, G>,
) -> bool
where
    F: 'afl + FnMut(&mut Unicorn<'a, D>, &mut [u8], i32) -> bool,
    G: 'afl + FnMut(&mut Unicorn<'a, D>, uc_error, &[u8], i32) -> bool,
{
    let user_data = &mut *user_data;
    debug_assert_eq!(uc, user_data.uc.inner().uc);
    debug_assert!(input_len >= 0);
    #[allow(clippy::cast_sign_loss)]
    let safe_input = core::slice::from_raw_parts_mut(input, input_len as usize);
    (user_data.input_callback)(&mut user_data.uc, safe_input, persistent_round)
}

unsafe extern "C" fn crash_validation_callback_proxy<'a, 'afl, D, F, G>(
    uc: uc_handle,
    error: uc_error,
    input: *mut u8,
    input_len: c_int,
    persistent_round: c_int,
    user_data: *mut AflFuzzCallback<'a, 'afl, D, F, G>,
) -> bool
where
    F: 'afl + FnMut(&mut Unicorn<'a, D>, &mut [u8], i32) -> bool,
    G: 'afl + FnMut(&mut Unicorn<'a, D>, uc_error, &[u8], i32) -> bool,
{
    let user_data = &mut *user_data;
    debug_assert_eq!(uc, user_data.uc.inner().uc);
    debug_assert!(input_len >= 0);
    #[allow(clippy::cast_sign_loss)]
    let safe_input = core::slice::from_raw_parts_mut(input, input_len as usize);
    (user_data.validate_callback)(&mut user_data.uc, error, safe_input, persistent_round)
}

/// Starts the AFL forkserver on some Unicorn emulation.
///
/// Multiple exit addresses can be specified. The Unicorn emulation has to be
/// started manually before by using `emu_start`.
pub fn afl_forkserver_start<'a, D>(uc: &mut Unicorn<'a, D>, exits: &[u64]) -> Result<(), AflRet> {
    let err = unsafe { uc_afl_forkserver_start(uc.inner().uc, exits.as_ptr(), exits.len()) };
    if err == AflRet::Error {
        Err(err)
    } else {
        Ok(())
    }
}

/// All-in-one fuzzing setup function.
///
/// This function can handle input reading and -placement within
/// emulation context, crash validation and persistent mode looping.
/// To use persistent mode, set `persistent_iters > 0` and
/// make sure to handle any necessary context restoration, e.g in the
/// `input_placement` callback.
pub fn afl_fuzz<'afl, 'a, D, F, G>(
    uc: &mut Unicorn<'a, D>,
    input_file: &str,
    input_placement_callback: F,
    exits: &[u64],
    crash_validation_callback: G,
    always_validate: bool,
    persistent_iters: u32,
) -> Result<(), AflRet>
where
    F: 'a + 'afl + FnMut(&mut Unicorn<'a, D>, &mut [u8], i32) -> bool,
    G: 'a + 'afl + FnMut(&mut Unicorn<'a, D>, uc_error, &[u8], i32) -> bool,
{
    let afl_fuzz_callback = Box::pin(AflFuzzCallback {
        input_callback: input_placement_callback,
        validate_callback: crash_validation_callback,
        uc: Unicorn {
            inner: uc.inner.clone(),
        },
        phantom: PhantomData,
    });

    #[allow(clippy::cast_possible_wrap)]
    let mut cstyle_input_file: Vec<i8> = input_file.bytes().map(|x| x as i8).collect();
    cstyle_input_file.push(0);

    let err = unsafe {
        uc_afl_fuzz(
            uc.inner_mut().uc,
            cstyle_input_file.as_ptr(),
            input_placement_callback_proxy::<'a, 'afl, D, F, G> as _,
            exits.as_ptr(),
            exits.len(),
            crash_validation_callback_proxy::<'a, 'afl, D, F, G> as _,
            always_validate,
            persistent_iters,
            &*afl_fuzz_callback as *const _ as _,
        )
    };
    if err == AflRet::Error {
        Err(err)
    } else {
        Ok(())
    }
}
