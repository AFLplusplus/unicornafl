use std::{
    hash::{Hash, Hasher},
    ops::Deref,
};

use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::{BytesInput, Input},
    observers::ValueObserver,
    state::HasExecutions,
};
use libafl_bolts::{
    ownedref::{OwnedRef, OwnedSlice},
    tuples::{tuple_list, tuple_list_type, RefIndexable},
};
use libafl_targets::EDGES_MAP_PTR;
use log::{trace, warn};
use serde::{Deserialize, Serialize};
use unicorn_engine::{uc_error, TcgOpCode, TcgOpFlag, UcHookId, Unicorn};

use crate::hash::afl_hash_ip;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnsafeSliceInput<'a> {
    pub input: OwnedSlice<'a, u8>,
}

impl<'a> Deref for UnsafeSliceInput<'a> {
    type Target = OwnedSlice<'a, u8>;
    fn deref(&self) -> &Self::Target {
        &self.input
    }
}

impl<'a> Hash for UnsafeSliceInput<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.input.to_vec().hash(state);
    }
}

impl<'a> UnsafeSliceInput<'a> {
    pub fn to_bytes_input(&self) -> BytesInput {
        BytesInput::new(self.input.to_vec())
    }
}

impl<'a> Input for UnsafeSliceInput<'a> {
    fn to_file<P>(&self, path: P) -> Result<(), libafl::Error>
    where
        P: AsRef<std::path::Path>,
    {
        self.to_bytes_input().to_file(path)
    }

    fn from_file<P>(path: P) -> Result<Self, libafl::Error>
    where
        P: AsRef<std::path::Path>,
    {
        let input = BytesInput::from_file(path)?;
        Ok(Self {
            input: OwnedSlice::from(input.into_inner()),
        })
    }
}

#[derive(Debug)]
struct HookState {
    prev_loc: u32,
    map_size: u32,
}

fn get_afl_map_size() -> u32 {
    std::env::var("AFL_MAP_SIZE")
        .ok()
        .map(|sz| u32::from_str_radix(&sz, 10).ok())
        .flatten()
        .unwrap_or(1 << 16) // MAP_SIZE
}

/// Data persisted during fuzzing. You can use `uc.get_data()`[Unicorn::get_data]
/// and `uc.get_data_mut()`[Unicorn::get_data_mut] to access this data in callbacks
/// and hooks during fuzzing.
///
/// You can create a default fuzz data by [`UnicornFuzzData::default()`] if you don't
/// want any custom data.
#[derive(Debug)]
pub struct UnicornFuzzData<D> {
    hook_state: HookState,
    /// User-defined data.
    pub user_data: D,
}

impl<D> UnicornFuzzData<D> {
    pub(crate) fn map_size(&self) -> u32 {
        self.hook_state.map_size
    }
}

impl Default for UnicornFuzzData<()> {
    fn default() -> Self {
        Self::new(())
    }
}

impl<D> UnicornFuzzData<D> {
    pub fn new(user_data: D) -> Self {
        Self {
            hook_state: HookState {
                prev_loc: 0,
                map_size: get_afl_map_size(),
            },
            user_data,
        }
    }
}

unsafe fn update_coverage(idx: usize) {
    unsafe {
        let loc = EDGES_MAP_PTR.byte_add(idx);
        let prev = *loc;
        *loc = prev + 1;
    }
}

unsafe fn update_with_prev(loc: u32, prev: u32) {
    let idx = prev ^ loc;
    update_coverage(idx as usize);
}

fn hook_code_coverage<'a, D: 'a>(
    uc: &mut Unicorn<'a, UnicornFuzzData<D>>,
    address: u64,
    _size: u32,
) {
    let state = &mut uc.get_data_mut().hook_state;
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

fn hook_opcode_cmpcov<'a, D: 'a>(
    uc: &mut Unicorn<'a, UnicornFuzzData<D>>,
    address: u64,
    arg1: u64,
    arg2: u64,
    size: usize,
) {
    let state = &mut uc.get_data_mut().hook_state;
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

/// Executor for unicorn
pub struct UnicornAflExecutor<'a, D, FI, FV, FC>
where
    D: 'a,
    FI: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>, &[u8], u64) -> bool + 'a,
    FV: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>, Result<(), uc_error>, &[u8], u64) -> bool + 'a,
    FC: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>) -> Result<(), uc_error> + 'a,
{
    uc: Unicorn<'a, UnicornFuzzData<D>>,
    /// Place the generated input into unicorn's memory.
    ///
    /// Return false if the generated input is not acceptable
    place_input_cb: FI,
    /// Return true if the crash is valid after validation
    validate_crash_cb: FV,
    /// The real procedure to kick unicorn engine start
    fuzz_callback: FC,
    /// Whether the `validate_crash_cb` is invoked everytime regardless of
    /// the execution result.
    ///
    /// If false, only execution failure will lead to the callback.
    always_validate: bool,
    /// Stored for deleting hook when dropping
    block_hook: UcHookId,
    /// Stored for deleting hook when dropping
    sub_hook: UcHookId,
    /// Stored for deleting hook when dropping
    cmp_hook: UcHookId,
    dumb_ob: tuple_list_type!(ValueObserver<'static, bool>),
}

impl<'a, D, FI, FV, FC> UnicornAflExecutor<'a, D, FI, FV, FC>
where
    D: 'a,
    FI: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>, &[u8], u64) -> bool + 'a,
    FV: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>, Result<(), uc_error>, &[u8], u64) -> bool + 'a,
    FC: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>) -> Result<(), uc_error> + 'a,
{
    /// Create a new executor
    pub fn new(
        mut uc: Unicorn<'a, UnicornFuzzData<D>>,
        place_input_cb: FI,
        validate_crash_cb: FV,
        fuzz_callback: FC,
        always_validate: bool,
        exits: Vec<u64>,
    ) -> Result<Self, uc_error> {
        if !exits.is_empty() {
            // Enable exits if requested
            uc.ctl_exits_enable().inspect_err(|ret| {
                warn!("Fail to enable exits due to {ret:?}");
            })?;
            uc.ctl_set_exits(&exits).inspect_err(|ret| {
                warn!("Fail to write exits due to {ret:?}");
            })?;
        }

        let block_hook = uc
            .add_block_hook(1, 0, |uc, address, size| {
                hook_code_coverage(uc, address, size);
            })
            .inspect_err(|ret| {
                warn!("Fail to add block hooks due to {ret:?}");
            })?;
        let sub_hook = uc
            .add_tcg_hook(
                TcgOpCode::SUB,
                TcgOpFlag::DIRECT,
                1,
                0,
                |uc, address, arg1, arg2, size| {
                    hook_opcode_cmpcov(uc, address, arg1, arg2, size);
                },
            )
            .inspect_err(|ret| {
                warn!("Fail to add sub hooks due to {ret:?}");
            })?;
        let cmp_hook = uc
            .add_tcg_hook(
                TcgOpCode::SUB,
                TcgOpFlag::CMP,
                1,
                0,
                |uc, address, arg1, arg2, size| {
                    hook_opcode_cmpcov(uc, address, arg1, arg2, size);
                },
            )
            .inspect_err(|ret| {
                warn!("Fail to add cmp hooks due to {ret:?}");
            })?;

        Ok(Self {
            uc,
            place_input_cb,
            validate_crash_cb,
            fuzz_callback,
            always_validate,
            block_hook,
            sub_hook,
            cmp_hook,
            dumb_ob: tuple_list!(ValueObserver::new("dumb_ob", OwnedRef::Owned(false.into()))),
        })
    }
}

impl<'a, D, FI, FV, FC> HasObservers for UnicornAflExecutor<'a, D, FI, FV, FC>
where
    D: 'a,
    FI: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>, &[u8], u64) -> bool + 'a,
    FV: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>, Result<(), uc_error>, &[u8], u64) -> bool + 'a,
    FC: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>) -> Result<(), uc_error> + 'a,
{
    type Observers = tuple_list_type!(ValueObserver<'static, bool>);
    fn observers(&self) -> libafl_bolts::tuples::RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.dumb_ob)
    }

    fn observers_mut(
        &mut self,
    ) -> libafl_bolts::tuples::RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.dumb_ob)
    }
}

impl<'a, D, FI, FV, FC> Drop for UnicornAflExecutor<'a, D, FI, FV, FC>
where
    D: 'a,
    FI: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>, &[u8], u64) -> bool + 'a,
    FV: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>, Result<(), uc_error>, &[u8], u64) -> bool + 'a,
    FC: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>) -> Result<(), uc_error> + 'a,
{
    fn drop(&mut self) {
        if let Err(ret) = self.uc.remove_hook(self.block_hook) {
            warn!("Fail to uninstall block hook due to {ret:?}");
        }
        if let Err(ret) = self.uc.remove_hook(self.sub_hook) {
            warn!("Fail to uninstall sub tcg opcode hook due to {ret:?}");
        }
        if let Err(ret) = self.uc.remove_hook(self.cmp_hook) {
            warn!("Fail to uninstall cmp tcg opcode hook due to {ret:?}");
        }
    }
}

impl<'a, 'b, EM, S, Z, D, FI, FV, FC> Executor<EM, UnsafeSliceInput<'a>, S, Z>
    for UnicornAflExecutor<'b, D, FI, FV, FC>
where
    S: HasExecutions,
    D: 'b,
    FI: FnMut(&mut Unicorn<'b, UnicornFuzzData<D>>, &[u8], u64) -> bool + 'b,
    FV: FnMut(&mut Unicorn<'b, UnicornFuzzData<D>>, Result<(), uc_error>, &[u8], u64) -> bool + 'b,
    FC: FnMut(&mut Unicorn<'b, UnicornFuzzData<D>>) -> Result<(), uc_error> + 'b,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &UnsafeSliceInput<'a>,
    ) -> Result<ExitKind, libafl::Error> {
        let accepted = (self.place_input_cb)(&mut self.uc, input.as_ref(), *state.executions());

        if !accepted {
            trace!("Input not accepted");
            return Ok(ExitKind::Ok);
        }

        let err = (self.fuzz_callback)(&mut self.uc);

        trace!("Child returns: {err:?}");

        if err.is_err() || self.always_validate {
            if (self.validate_crash_cb)(&mut self.uc, err, input.as_ref(), *state.executions()) {
                return Ok(ExitKind::Crash);
            }
        }

        Ok(ExitKind::Ok)
    }
}
