#![allow(non_camel_case_types)]
#![allow(dead_code)]


use std::ffi::c_void;
use std::pin::Pin;
use libc::{c_char, c_int};
use super::unicorn_const::*;

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
    pub fn uc_mem_protect(engine: uc_handle, address: u64, size: libc::size_t, perms: u32)
        -> uc_error;
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
        exit_count: libc::size_t
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
        data: *mut c_void
    ) -> AflRet;
}


pub struct CodeHook<D> {
    pub unicorn: *mut crate::UnicornInner<D>,
    pub callback: Box<dyn FnMut(crate::UnicornHandle<D>, u64, u32)>
}

pub struct BlockHook<D> {
    pub unicorn: *mut crate::UnicornInner<D>,
    pub callback: Box<dyn FnMut(crate::UnicornHandle<D>, u64, u32)>
}

pub struct MemHook<D> {
    pub unicorn: *mut crate::UnicornInner<D>,
    pub callback: Box<dyn FnMut(crate::UnicornHandle<D>, MemType, u64, usize, i64)>
}

pub struct InterruptHook<D> {
    pub unicorn: *mut crate::UnicornInner<D>,
    pub callback: Box<dyn FnMut(crate::UnicornHandle<D>, u32)>
}

pub struct InstructionInHook<D> {
    pub unicorn: *mut crate::UnicornInner<D>,
    pub callback: Box<dyn FnMut(crate::UnicornHandle<D>, u32, usize)>
}

pub struct InstructionOutHook<D> {
    pub unicorn: *mut crate::UnicornInner<D>,
    pub callback: Box<dyn FnMut(crate::UnicornHandle<D>, u32, usize, u32)>
}

pub struct InstructionSysHook<D> {
    pub unicorn: *mut crate::UnicornInner<D>,
    pub callback: Box<dyn FnMut(crate::UnicornHandle<D>)>
}

pub struct AflFuzzCallback<D> {
    pub unicorn: *mut crate::UnicornInner<D>,
    pub input_callback: Box<dyn FnMut(crate::UnicornHandle<D>, &mut [u8], i32) -> bool>,
    pub validate_callback: Box<dyn FnMut(crate::UnicornHandle<D>, uc_error, &[u8], i32) -> bool>
}

pub extern "C" fn code_hook_proxy<D>(uc: uc_handle, address: u64, size: u32, user_data: *mut CodeHook<D>) {
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = &mut unsafe { &mut *(*user_data).callback };
    assert_eq!(uc, unicorn.uc);
    callback(crate::UnicornHandle { inner: unsafe { Pin::new_unchecked(unicorn) } }, address, size);
}

pub extern "C" fn block_hook_proxy<D>(uc: uc_handle, address: u64, size: u32, user_data: *mut BlockHook<D>) {
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = &mut unsafe { &mut *(*user_data).callback };
    assert_eq!(uc, unicorn.uc);
    callback(crate::UnicornHandle { inner: unsafe { Pin::new_unchecked(unicorn) } }, address, size);
}

pub extern "C" fn mem_hook_proxy<D>(uc: uc_handle, 
        mem_type: MemType, 
        address: u64, 
        size: u32, 
        value: i64, 
        user_data: *mut MemHook<D>) 
{
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = &mut unsafe { &mut *(*user_data).callback };
    assert_eq!(uc, unicorn.uc);
    callback(crate::UnicornHandle { inner: unsafe { Pin::new_unchecked(unicorn) } }, mem_type, address, size as usize, value);
}

pub extern "C" fn intr_hook_proxy<D>(uc: uc_handle, value: u32, user_data: *mut InterruptHook<D>) {
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = &mut unsafe { &mut *(*user_data).callback };
    assert_eq!(uc, unicorn.uc);
    callback(crate::UnicornHandle { inner: unsafe { Pin::new_unchecked(unicorn) } }, value);
}

pub extern "C" fn insn_in_hook_proxy<D>(
        uc: uc_handle, 
        port: u32, 
        size: usize, 
        user_data: *mut InstructionInHook<D>) {
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = &mut unsafe { &mut *(*user_data).callback };
    assert_eq!(uc, unicorn.uc);
    callback(crate::UnicornHandle { inner: unsafe { Pin::new_unchecked(unicorn) } }, port, size);
}

pub extern "C" fn insn_out_hook_proxy<D>(
        uc: uc_handle, 
        port: u32, 
        size: usize, 
        value: u32,
        user_data: *mut InstructionOutHook<D>) {
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = &mut unsafe { &mut *(*user_data).callback };
    assert_eq!(uc, unicorn.uc);
    callback(crate::UnicornHandle { inner: unsafe { Pin::new_unchecked(unicorn) } }, port, size, value);
}

pub extern "C" fn insn_sys_hook_proxy<D>(uc: uc_handle, user_data: *mut InstructionSysHook<D>) {
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = &mut unsafe { &mut *(*user_data).callback };
    assert_eq!(uc, unicorn.uc);
    callback(crate::UnicornHandle { inner: unsafe { Pin::new_unchecked(unicorn) } });
}

#[inline]
pub extern "C" fn input_placement_callback_proxy<D>(uc: uc_handle,
    input: *mut u8,
    input_len: c_int,
    persistent_round: c_int,
    user_data: *mut AflFuzzCallback<D>) -> bool {
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = &mut unsafe { &mut *(*user_data).input_callback };
    let safe_input = unsafe { std::slice::from_raw_parts_mut(input, input_len as usize) };
    assert_eq!(uc, unicorn.uc);
    callback(crate::UnicornHandle { inner: unsafe { Pin::new_unchecked(unicorn) } }, safe_input, persistent_round)
}

#[inline]
pub extern "C" fn crash_validation_callback_proxy<D>(uc: uc_handle,
    unicorn_result: uc_error,
    input: *const u8,
    input_len: c_int,
    persistent_round: c_int,
    user_data: *mut AflFuzzCallback<D>
    ) -> bool {
    let unicorn = unsafe { &mut *(*user_data).unicorn };
    let callback = &mut unsafe { &mut *(*user_data).validate_callback };
    assert_eq!(uc, unicorn.uc);
    let safe_input = unsafe { std::slice::from_raw_parts(input, input_len as usize) };
    callback(crate::UnicornHandle { inner: unsafe { Pin::new_unchecked(unicorn) } }, 
        unicorn_result, safe_input, persistent_round) 
}
