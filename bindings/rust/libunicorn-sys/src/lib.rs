#![deny(rust_2018_idioms)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod unicorn_const;
pub mod arm64_const;
pub mod arm_const;
pub mod m68k_const;
pub mod mips_const;
pub mod sparc_const;
pub mod x86_const;

use crate::unicorn_const::{Arch, Error, HookType, Mode, Query, Protection};
use core::{fmt, slice};
use libc::{c_char, c_int, c_void};

#[allow(non_camel_case_types)]
pub type uc_handle = libc::size_t;
#[allow(non_camel_case_types)]
pub type uc_hook = libc::size_t;
#[allow(non_camel_case_types)]
pub type uc_context = libc::size_t;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct MemRegion {
    /// The start address of the region (inclusive).
    pub begin: u64,
    /// The end address of the region (inclusive).
    pub end: u64,
    /// The memory permissions of the region.
    pub perms: Protection,
}

extern "C" {
    pub fn uc_version(major: *mut u32, minor: *mut u32) -> u32;
    pub fn uc_arch_supported(arch: Arch) -> bool;
    pub fn uc_open(arch: Arch, mode: Mode, engine: *mut uc_handle) -> Error;
    pub fn uc_close(engine: uc_handle) -> Error;
    pub fn uc_free(mem: libc::size_t) -> Error;
    pub fn uc_errno(engine: uc_handle) -> Error;
    pub fn uc_strerror(error_code: Error) -> *const c_char;
    pub fn uc_reg_write(engine: uc_handle, regid: c_int, value: *const c_void) -> Error;
    pub fn uc_reg_read(engine: uc_handle, regid: c_int, value: *mut c_void) -> Error;
    pub fn uc_mem_write(
        engine: uc_handle,
        address: u64,
        bytes: *const u8,
        size: libc::size_t,
    ) -> Error;
    pub fn uc_mem_read(
        engine: uc_handle,
        address: u64,
        bytes: *mut u8,
        size: libc::size_t,
    ) -> Error;
    pub fn uc_mem_map(engine: uc_handle, address: u64, size: libc::size_t, perms: u32) -> Error;
    pub fn uc_mem_map_ptr(
        engine: uc_handle,
        address: u64,
        size: libc::size_t,
        perms: u32,
        ptr: *mut c_void,
    ) -> Error;
    pub fn uc_mem_unmap(engine: uc_handle, address: u64, size: libc::size_t) -> Error;
    pub fn uc_mem_protect(engine: uc_handle, address: u64, size: libc::size_t, perms: u32)
        -> Error;
    pub fn uc_mem_regions(
        engine: uc_handle,
        regions: *const *const MemRegion,
        count: *mut u32,
    ) -> Error;
    pub fn uc_emu_start(
        engine: uc_handle,
        begin: u64,
        until: u64,
        timeout: u64,
        count: libc::size_t,
    ) -> Error;
    pub fn uc_emu_stop(engine: uc_handle) -> Error;
    pub fn uc_hook_add(
        engine: uc_handle,
        hook: *mut uc_hook,
        hook_type: HookType,
        callback: libc::size_t,
        user_data: *mut libc::size_t,
        begin: u64,
        end: u64,
        ...
    ) -> Error;
    pub fn uc_hook_del(engine: uc_handle, hook: uc_hook) -> Error;
    pub fn uc_query(engine: uc_handle, query_type: Query, result: *mut libc::size_t) -> Error;
    pub fn uc_context_alloc(engine: uc_handle, context: *mut uc_context) -> Error;
    pub fn uc_context_save(engine: uc_handle, context: uc_context) -> Error;
    pub fn uc_context_restore(engine: uc_handle, context: uc_context) -> Error;


/* Callback function called for each input from AFL.
 This function is mandatory.
 It's purpose is to place the input at the right place in unicorn.

 @uc: Unicorn instance
 @input: The current input we're workin on. Place this somewhere in unicorn's memory now.
 @input_len: length of the input
 @persistent_round: which round we are currently crashing in, if using persistent mode.
 @data: Data pointer passed to uc_afl_fuzz(...).

 @return:
  If you return is true, all is well. Fuzzing starts.
  If you return false, something has gone wrong. the execution loop will exit. 
    There should be no reason to do this in a usual usecase.
*/
//typedef bool (*uc_afl_cb_place_input_t)(uc_engine *uc, char *input, size_t input_len, uint32_t persistent_round, void *data);

/* Callback function called after a non-UC_ERR_OK returncode was returned by Unicorn. 
 This function is not mandatory (pass NULL).
 @uc: Unicorn instance
 @unicorn_result: The error state returned by the current testcase
 @input: The current input we're workin with.
 @input_len: length of the input
 @persistent_round: which round we are currently crashing in, if using persistent mode.
 @data: Data pointer passed to uc_afl_fuzz(...).

@Return:
  If you return false, the crash is considered invalid and not reported to AFL.
  If return is true, the crash is reported. 
  -> The child will die and the forkserver will spawn a new child.
*/
//typedef bool (*uc_afl_cb_validate_crash_t)(uc_engine *uc, uc_err unicorn_result, char *input, int input_len, int persistent_round, void *data);

//typedef bool (*uc_afl_cb_place_input_t)(uc_engine *uc, char *input, size_t input_len, uint32_t persistent_round, void *data);
    pub fn uc_afl_fuzz(
        engine: uc_handle, 
        input_file: *const u8,
        place_input_callback: *mut libc::c_void,
        exits: *const u64,
        exit_count: libc::size_t,
        validate_crash_callback: *mut libc::c_void,
        always_validate: bool,
        persistent_iters: u32,
        data: *const c_void
    ) -> unicorn_const::AflRet;

        //where F:
        //    Fn(uc_handle, Error, libc::c_void, libc::c_int, libc::c_int, libc::c_void) -> bool;
        
        // Fn<libc::bool, uc_handle, Error, libc::void, libc::int, libc::int, libc::void>, 

    pub fn uc_afl_forkserver_start(
        engine: uc_handle,
        exits: *const u64,
        exit_count: libc::size_t
    ) -> unicorn_const::AflRet;

    /* A start with "less features" for our afl use-case */
    /* this is largely copied from uc_emu_start, just without setting the entry point, counter and timeout. */
    pub fn uc_afl_emu_start(engine: uc_handle) -> Error;

    pub fn uc_afl_next(engine: uc_handle) -> unicorn_const::AflRet;

}

impl Error {
    pub fn msg(self) -> &'static str {
        unsafe {
            let ptr = uc_strerror(self);
            let len = libc::strlen(ptr);
            let s = slice::from_raw_parts(ptr as *const u8, len);
            // We believe that strings returned by `uc_strerror` are always valid ASCII chars.
            // Hence they also must be a valid Rust str.
            core::str::from_utf8_unchecked(s)
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.msg().fmt(fmt)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
