use std::os::raw::c_void;

use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::BytesInput,
    observers::ValueObserver,
    state::HasExecutions,
};
use libafl_bolts::{
    ownedref::OwnedRef,
    tuples::{tuple_list, tuple_list_type, RefIndexable},
    HasLen,
};
use libafl_targets::EDGES_MAP_PTR;
use log::{debug, warn};
use unicorn_engine::{
    ffi::{uc_ctl, uc_handle, uc_hook, uc_hook_add, uc_hook_del},
    uc_error, ControlType,
};

use crate::{
    hash::afl_hash_ip, uc_afl_cb_place_input_t, uc_afl_cb_validate_crash_t, uc_afl_fuzz_cb_t,
};

#[derive(Debug)]
struct HookState {
    prev_loc: u32,
    map_size: u32,
}

unsafe fn update_coverage(idx: usize) {
    unsafe {
        let loc = EDGES_MAP_PTR.byte_add(idx);
        let prev = *loc;
        *loc = prev + 1;
    }
}

unsafe fn update_with_prev(loc: u32, prev: u32) {
    update_coverage((prev ^ loc) as usize);
}

#[no_mangle]
extern "C" fn hook_code_coverage(_uc: uc_handle, address: u64, _size: u32, data: *mut c_void) {
    let state: &mut HookState = unsafe { (data as *mut HookState).as_mut().unwrap() };
    let cur_loc = afl_hash_ip(address) & (state.map_size - 1);

    unsafe { update_with_prev(cur_loc, state.prev_loc) };
    state.prev_loc = cur_loc >> 1;
}

fn hook_sub_impl_16(cur_loc: u32, prev_loc: u32, arg1: u64, arg2: u64) {
    if (arg1 & 0xff00) == (arg2 & 0xff00) {
        unsafe { update_with_prev(cur_loc, prev_loc) }
    }
}

fn hook_sub_impl_32(cur_loc: u32, prev_loc: u32, arg1: u64, arg2: u64) {
    if (arg1 & 0xff000000) == (arg2 & 0xff000000) {
        unsafe { update_with_prev(cur_loc + 2, prev_loc) }
        if (arg1 & 0xff0000) == (arg2 & 0xff0000) {
            unsafe { update_with_prev(cur_loc + 1, prev_loc) }
            if (arg1 & 0xff00) == (arg2 & 0xff00) {
                unsafe { update_with_prev(cur_loc, prev_loc) }
            }
        }
    }
}

fn hook_sub_impl_64(cur_loc: u32, prev_loc: u32, arg1: u64, arg2: u64) {
    if (arg1 & 0xff00000000000000) == (arg2 & 0xff00000000000000) {
        unsafe { update_with_prev(cur_loc + 6, prev_loc) }
        if (arg1 & 0xff000000000000) == (arg2 & 0xff000000000000) {
            unsafe { update_with_prev(cur_loc + 5, prev_loc) }
            if (arg1 & 0xff0000000000) == (arg2 & 0xff0000000000) {
                unsafe { update_with_prev(cur_loc + 4, prev_loc) }
                if (arg1 & 0xff00000000) == (arg2 & 0xff00000000) {
                    unsafe { update_with_prev(cur_loc + 3, prev_loc) }
                    if (arg1 & 0xff000000) == (arg2 & 0xff000000) {
                        unsafe { update_with_prev(cur_loc + 2, prev_loc) }
                        if (arg1 & 0xff0000) == (arg2 & 0xff0000) {
                            unsafe { update_with_prev(cur_loc + 1, prev_loc) }
                            if (arg1 & 0xff00) == (arg2 & 0xff00) {
                                unsafe { update_with_prev(cur_loc, prev_loc) }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[no_mangle]
extern "C" fn hook_opcode_cmpcov(
    _uc: uc_handle,
    address: u64,
    arg1: u64,
    arg2: u64,
    size: u32,
    data: *mut c_void,
) {
    let state: &mut HookState = unsafe { (data as *mut HookState).as_mut().unwrap() };
    let mut cur_loc = afl_hash_ip(address) & (state.map_size - 1);

    if size >= 64 {
        if cur_loc + 8 >= state.map_size {
            cur_loc -= 8;
        }
        hook_sub_impl_64(cur_loc, state.prev_loc, arg1, arg2);
    } else if size >= 32 {
        if cur_loc + 4 >= state.map_size {
            cur_loc -= 4;
        }
        hook_sub_impl_32(cur_loc, state.prev_loc, arg1, arg2);
    } else {
        if cur_loc + 2 >= state.map_size {
            cur_loc -= 2;
        }
        hook_sub_impl_16(cur_loc, state.prev_loc, arg1, arg2);
    }
}

#[derive(Debug)]
pub struct UnicornAflExecutor {
    uc: uc_handle,
    place_input_cb: uc_afl_cb_place_input_t,
    validate_crash_cb: Option<uc_afl_cb_validate_crash_t>,
    fuzz_callback: uc_afl_fuzz_cb_t,
    always_validate: bool,
    exits: Vec<u64>,
    data: *mut c_void,
    state: Box<HookState>,
    block_hook: uc_hook,
    cmp_hook: uc_hook,
    sub_hook: uc_hook,
    dumb_ob: tuple_list_type!(ValueObserver<'static, ()>),
}

impl UnicornAflExecutor {
    pub fn new(
        uc: uc_handle,
        place_input_cb: uc_afl_cb_place_input_t,
        validate_crash_cb: Option<uc_afl_cb_validate_crash_t>,
        fuzz_callback: uc_afl_fuzz_cb_t,
        always_validate: bool,
        exits: Vec<u64>,
        map_size: u32,
        data: *mut c_void,
    ) -> Result<Self, uc_error> {
        let mut block_hook = std::ptr::null_mut();
        let mut cmp_hook = std::ptr::null_mut();
        let mut sub_hook = std::ptr::null_mut();
        let mut state = Box::new(HookState {
            prev_loc: 0,
            map_size,
        });
        unsafe {
            // Enable exits if requested
            if exits.len() > 0 {
                let ret = uc_ctl(
                    uc,
                    ControlType::UC_CTL_IO_WRITE as u32 | ControlType::UC_CTL_UC_USE_EXITS as u32,
                    1u32,
                );
                if ret != uc_error::OK {
                    return Err(ret);
                }
                let ret = uc_ctl(
                    uc,
                    ControlType::UC_CTL_IO_WRITE as u32 | ControlType::UC_CTL_UC_EXITS as u32,
                    exits.as_ptr(),
                    exits.len(),
                );
                if ret != uc_error::OK {
                    return Err(ret);
                }
            }

            let ret = uc_hook_add(
                uc,
                &mut block_hook,
                unicorn_engine::HookType::BLOCK,
                hook_code_coverage as _,
                state.as_mut() as *mut HookState as _,
                1,
                0,
            );
            if ret != uc_error::OK {
                return Err(ret);
            }
            let ret = uc_hook_add(
                uc,
                &mut cmp_hook,
                unicorn_engine::HookType::TCG_OPCODE,
                hook_opcode_cmpcov as _,
                state.as_mut() as *mut HookState as _,
                1,
                0,
                unicorn_engine::TcgOp::SUB,
                unicorn_engine::TcgOpFlag::CMP,
            );
            if ret != uc_error::OK {
                return Err(ret);
            }
            let ret = uc_hook_add(
                uc,
                &mut sub_hook,
                unicorn_engine::HookType::TCG_OPCODE,
                hook_opcode_cmpcov as _,
                state.as_mut() as *mut HookState as _,
                1,
                0,
                unicorn_engine::TcgOp::SUB,
                unicorn_engine::TcgOpFlag::DIRECT,
            );
            if ret != uc_error::OK {
                return Err(ret);
            }
        }
        Ok(Self {
            uc,
            place_input_cb,
            validate_crash_cb,
            fuzz_callback,
            always_validate,
            exits,
            data,
            state,
            block_hook,
            cmp_hook,
            sub_hook,
            dumb_ob: tuple_list!(ValueObserver::new("dumb_ob", OwnedRef::Owned(().into()))),
        })
    }
}

impl HasObservers for UnicornAflExecutor {
    type Observers = tuple_list_type!(ValueObserver<'static, ()>);
    fn observers(&self) -> libafl_bolts::tuples::RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.dumb_ob)
    }

    fn observers_mut(
        &mut self,
    ) -> libafl_bolts::tuples::RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.dumb_ob)
    }
}

impl Drop for UnicornAflExecutor {
    fn drop(&mut self) {
        unsafe {
            let ret = uc_hook_del(self.uc, self.block_hook);
            if ret != uc_error::OK {
                warn!("Fail to uninstall block hook due to {:?}", ret)
            }
            let ret = uc_hook_del(self.uc, self.cmp_hook);
            if ret != uc_error::OK {
                warn!("Fail to uninstall cmp tcg opcode hook due to {:?}", ret);
            }
            let ret = uc_hook_del(self.uc, self.sub_hook);
            if ret != uc_error::OK {
                warn!("Fail to uninstall sub tcg opcode hook due to {:?}", ret);
            }
        }
    }
}

impl<EM, S, Z> Executor<EM, BytesInput, S, Z> for UnicornAflExecutor
where
    S: HasExecutions,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &BytesInput,
    ) -> Result<ExitKind, libafl::Error> {
        let accepted = (self.place_input_cb)(
            self.uc,
            input.as_ref().as_ptr(),
            input.len(),
            *state.executions(),
            self.data,
        );

        if !accepted {
            debug!("Input not accepted");
            return Ok(ExitKind::Ok);
        }

        let err = (self.fuzz_callback)(self.uc, self.data);

        debug!("Child returns: {:?}", err);

        if err != uc_error::OK || self.always_validate {
            if let Some(validate_cb) = self.validate_crash_cb {
                if (validate_cb)(
                    self.uc,
                    err,
                    input.as_ref().as_ptr(),
                    input.len(),
                    *state.executions(),
                    self.data,
                ) {
                    return Ok(ExitKind::Crash);
                }
            }
        }

        Ok(ExitKind::Ok)
    }
}
