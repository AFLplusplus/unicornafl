#![allow(non_camel_case_types)]
#![allow(dead_code)]

use super::unicorn_const::*;
use libc::{c_char, c_int};
use std::ffi::c_void;

pub type uc_handle = *mut c_void;
pub type uc_hook = *mut c_void;
pub type uc_context = libc::size_t;

extern "C" {
    pub fn uc_version(major: *mut u32, minor: *mut u32) -> u32;
    pub fn uc_arch_supported(arch: Arch) -> bool;
    pub fn uc_open(arch: Arch, mode: Mode, engine: *mut uc_handle) -> uc_error;
    pub fn uc_close(engine: uc_handle) -> uc_error;
    pub fn uc_free(mem: uc_context) -> uc_error;
    pub fn uc_errno(engine: uc_handle) -> uc_error;
    pub fn uc_strerror(error_code: uc_error) -> *const c_char;
    pub fn uc_reg_write(engine: uc_handle, regid: c_int, value: *const c_void) -> uc_error;
    pub fn uc_reg_read(engine: uc_handle, regid: c_int, value: *mut c_void) -> uc_error;
    pub fn uc_mem_write(
        engine: uc_handle,
        address: u64,
        bytes: *const u8,
        size: libc::size_t,
    ) -> uc_error;
    pub fn uc_mem_read(
        engine: uc_handle,
        address: u64,
        bytes: *mut u8,
        size: libc::size_t,
    ) -> uc_error;
    pub fn uc_mem_map(engine: uc_handle, address: u64, size: libc::size_t, perms: u32) -> uc_error;
    pub fn uc_mem_map_ptr(
        engine: uc_handle,
        address: u64,
        size: libc::size_t,
        perms: u32,
        ptr: *mut c_void,
    ) -> uc_error;
    pub fn uc_mem_unmap(engine: uc_handle, address: u64, size: libc::size_t) -> uc_error;
    pub fn uc_mem_protect(
        engine: uc_handle,
        address: u64,
        size: libc::size_t,
        perms: u32,
    ) -> uc_error;
    pub fn uc_mem_regions(
        engine: uc_handle,
        regions: *const *const MemRegion,
        count: *mut u32,
    ) -> uc_error;
    pub fn uc_emu_start(
        engine: uc_handle,
        begin: u64,
        until: u64,
        timeout: u64,
        count: libc::size_t,
    ) -> uc_error;
    pub fn uc_emu_stop(engine: uc_handle) -> uc_error;
    pub fn uc_hook_add(
        engine: uc_handle,
        hook: *mut uc_hook,
        hook_type: HookType,
        callback: *mut c_void,
        user_data: *mut c_void,
        begin: u64,
        end: u64,
        ...
    ) -> uc_error;
    pub fn uc_hook_del(engine: uc_handle, hook: uc_hook) -> uc_error;
    pub fn uc_query(engine: uc_handle, query_type: Query, result: *mut libc::size_t) -> uc_error;
    pub fn uc_context_alloc(engine: uc_handle, context: *mut uc_context) -> uc_error;
    pub fn uc_context_save(engine: uc_handle, context: uc_context) -> uc_error;
    pub fn uc_context_restore(engine: uc_handle, context: uc_context) -> uc_error;
    pub fn uc_afl_forkserver_start(
        engine: uc_handle,
        exits: *const u64,
        exit_count: libc::size_t,
    ) -> AflRet;
    pub fn uc_afl_fuzz(
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

pub struct UcHook<'a, D: 'a, F: 'a> {
    pub unicorn: *mut crate::Unicorn<'a, D>,
    pub callback: F,
}

pub trait IsUcHook<'a> {}

impl<'a, D, F> IsUcHook<'a> for UcHook<'a, D, F> {}

pub extern "C" fn code_hook_proxy<D, F>(
    uc: uc_handle,
    address: u64,
    size: u32,
    user_data: *mut UcHook<D, F>,
) where
    F: FnMut(&mut crate::Unicorn<D>, u64, u32),
{
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = unsafe { &mut (*user_data).callback };
    assert_eq!(uc, unicorn.inner.uc);
    callback(unicorn, address, size);
}

pub extern "C" fn block_hook_proxy<D, F>(
    uc: uc_handle,
    address: u64,
    size: u32,
    user_data: *mut UcHook<D, F>,
) where
    F: FnMut(&mut crate::Unicorn<D>, u64, u32),
{
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = unsafe { &mut (*user_data).callback };
    assert_eq!(uc, unicorn.inner.uc);
    callback(unicorn, address, size);
}

pub extern "C" fn mem_hook_proxy<D, F>(
    uc: uc_handle,
    mem_type: MemType,
    address: u64,
    size: u32,
    value: i64,
    user_data: *mut UcHook<D, F>,
) -> bool
where
    F: FnMut(&mut crate::Unicorn<D>, MemType, u64, usize, i64) -> bool,
{
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = unsafe { &mut (*user_data).callback };
    assert_eq!(uc, unicorn.inner.uc);
    callback(unicorn, mem_type, address, size as usize, value)
}

pub extern "C" fn intr_hook_proxy<D, F>(uc: uc_handle, value: u32, user_data: *mut UcHook<D, F>)
where
    F: FnMut(&mut crate::Unicorn<D>, u32),
{
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = unsafe { &mut (*user_data).callback };
    assert_eq!(uc, unicorn.inner.uc);
    callback(unicorn, value);
}

pub extern "C" fn insn_in_hook_proxy<D, F>(
    uc: uc_handle,
    port: u32,
    size: usize,
    user_data: *mut UcHook<D, F>,
) where
    F: FnMut(&mut crate::Unicorn<D>, u32, usize),
{
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = unsafe { &mut (*user_data).callback };
    assert_eq!(uc, unicorn.inner.uc);
    callback(unicorn, port, size);
}

pub extern "C" fn insn_out_hook_proxy<D, F>(
    uc: uc_handle,
    port: u32,
    size: usize,
    value: u32,
    user_data: *mut UcHook<D, F>,
) where
    F: FnMut(&mut crate::Unicorn<D>, u32, usize, u32),
{
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = unsafe { &mut (*user_data).callback };
    assert_eq!(uc, unicorn.inner.uc);
    callback(unicorn, port, size, value);
}

pub extern "C" fn insn_sys_hook_proxy<D, F>(uc: uc_handle, user_data: *mut UcHook<D, F>)
where
    F: FnMut(&mut crate::Unicorn<D>),
{
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    assert_eq!(uc, unicorn.inner.uc);
    let callback = unsafe { &mut (*user_data).callback };
    callback(unicorn);
}
