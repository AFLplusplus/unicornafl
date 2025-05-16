//! Executor to conduct unicorn afl fuzzing in one execution round.

use std::{
    io::{PipeReader, PipeWriter},
    marker::PhantomData,
};

use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::HasTargetBytes,
    observers::ObserversTuple,
    state::HasExecutions,
};
use libafl_bolts::tuples::RefIndexable;
use libafl_targets::{CMPLOG_MAP_W, EDGES_MAP_PTR};
use log::{debug, error, trace, warn};
use unicorn_engine::{TcgOpCode, TcgOpFlag, UcHookId, Unicorn, uc_error};

use crate::hash::afl_hash_ip;

/// State for hook edge
#[derive(Debug)]
struct HookState {
    prev_loc: u32,
    map_size: u32,
}

fn get_afl_map_size() -> u32 {
    std::env::var("AFL_MAP_SIZE")
        .ok()
        .and_then(|sz| sz.parse::<u32>().ok())
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
    /// Store write side to child pipe. Closed when dropping
    pub(crate) child_pipe_w: Option<PipeWriter>,
    /// Store read side to parent pipe. Closed when dropping
    pub(crate) parent_pipe_r: Option<PipeReader>,
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
    /// Create a new unicorn fuzz data.
    ///
    /// This will try to retrieve env `AFL_MAP_SIZE` to determine map size, and
    /// fill the default value if no such env.
    pub fn new(user_data: D) -> Self {
        Self {
            hook_state: HookState {
                prev_loc: 0,
                map_size: get_afl_map_size(),
            },
            user_data,
            child_pipe_w: None,
            parent_pipe_r: None,
        }
    }

    /// Clear hook state. Always call this method before each execution
    pub(crate) fn clear_prev_loc(&mut self) {
        self.hook_state.prev_loc = 0;
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
    unsafe {
        update_coverage(idx as usize);
    }
}

fn hook_code_coverage<'a, D: 'a>(
    uc: &mut Unicorn<'a, UnicornFuzzData<D>>,
    address: u64,
    _size: u32,
) {
    let state = &mut uc.get_data_mut().hook_state;
    let cur_loc = afl_hash_ip(address) & (state.map_size - 1);
    trace!(
        "Coverage address={} prev={} cur_loc={}",
        address, state.prev_loc, cur_loc
    );
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
    let state = &uc.get_data().hook_state;
    let mut cur_loc = afl_hash_ip(address) & (state.map_size - 1);

    trace!(
        "Compcov address={} arg1={} arg2={} size={} cur_loc={}",
        address, arg1, arg2, size, cur_loc
    );
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

fn hook_opcode_cmplog<'a, D: 'a>(
    uc: &mut Unicorn<'a, UnicornFuzzData<D>>,
    address: u64,
    arg1: u64,
    arg2: u64,
    size: usize,
) {
    let state = &uc.get_data().hook_state;
    let cur_loc = afl_hash_ip(address) & (state.map_size - 1);
    let k = cur_loc as usize & (CMPLOG_MAP_W - 1);
    let shape = match size {
        16 => 1,
        32 => 3,
        64 => 7,
        _ => 0,
    };

    unsafe {
        libafl_targets::cmps::__libafl_targets_cmplog_instructions(k, shape, arg1, arg2);
    }
}

/// Callbacks for each execution round
pub trait UnicornAflExecutorHook<'a, D> {
    /// Place the generated input into unicorn's memory.
    ///
    /// Return false if the generated input is not acceptable
    fn place_input(
        &mut self,
        uc: &mut Unicorn<'a, UnicornFuzzData<D>>,
        input: &[u8],
        persistent_round: u64,
    ) -> bool;

    /// Return true if the crash is valid after validation.
    ///
    /// The default implementation is [`dummy_uc_validate_crash_callback`][crate::target::dummy_uc_validate_crash_callback]
    fn validate_crash(
        &mut self,
        uc: &mut Unicorn<'a, UnicornFuzzData<D>>,
        unicorn_result: Result<(), uc_error>,
        input: &[u8],
        persistent_round: u64,
    ) -> bool {
        crate::target::dummy_uc_validate_crash_callback(uc, unicorn_result, input, persistent_round)
    }

    /// The real procedure to kick unicorn engine start
    ///
    /// The default implementation is [`dummy_uc_fuzz_callback`][crate::target::dummy_uc_fuzz_callback]
    fn fuzz(&mut self, uc: &mut Unicorn<'a, UnicornFuzzData<D>>) -> Result<(), uc_error> {
        crate::target::dummy_uc_fuzz_callback(uc)
    }
}

/// Convenient struct to create a [`UnicornAflExecutorHook`] from closures
pub struct UnicornAflExecutorCustomHook<'a, D, FI, FV, FC> {
    place_input_callback: FI,
    validate_crash_callback: FV,
    fuzz_callback: FC,
    phantom: PhantomData<&'a D>,
}

impl<'a, D, FI, FV, FC> UnicornAflExecutorCustomHook<'a, D, FI, FV, FC>
where
    FI: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>, &[u8], u64) -> bool + 'a,
    FV: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>, Result<(), uc_error>, &[u8], u64) -> bool + 'a,
    FC: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>) -> Result<(), uc_error> + 'a,
{
    /// Create a new custom hook from closures
    pub fn new(place_input_callback: FI, validate_crash_callback: FV, fuzz_callback: FC) -> Self {
        Self {
            place_input_callback,
            validate_crash_callback,
            fuzz_callback,
            phantom: PhantomData,
        }
    }
}

impl<'a, D, FI, FV, FC> UnicornAflExecutorHook<'a, D>
    for UnicornAflExecutorCustomHook<'a, D, FI, FV, FC>
where
    FI: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>, &[u8], u64) -> bool + 'a,
    FV: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>, Result<(), uc_error>, &[u8], u64) -> bool + 'a,
    FC: FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>) -> Result<(), uc_error> + 'a,
{
    fn place_input(
        &mut self,
        uc: &mut Unicorn<'a, UnicornFuzzData<D>>,
        input: &[u8],
        persistent_round: u64,
    ) -> bool {
        (self.place_input_callback)(uc, input, persistent_round)
    }

    fn validate_crash(
        &mut self,
        uc: &mut Unicorn<'a, UnicornFuzzData<D>>,
        unicorn_result: Result<(), uc_error>,
        input: &[u8],
        persistent_round: u64,
    ) -> bool {
        (self.validate_crash_callback)(uc, unicorn_result, input, persistent_round)
    }

    fn fuzz(&mut self, uc: &mut Unicorn<'a, UnicornFuzzData<D>>) -> Result<(), uc_error> {
        (self.fuzz_callback)(uc)
    }
}

#[derive(Debug, Clone, Copy)]
/// Policy to deal with CMP and SUB instructions
pub enum CmpPolicy {
    /// Use Redqueen algorithm
    ///
    /// To use this policy, users should first setup [`CMPLOG_MAP_PTR`][libafl_targets::cmps::CMPLOG_MAP_PTR]
    /// by methods like [`map_cmplog_shared_memory`][libafl_targets::map_cmplog_shared_memory]
    Cmplog,
    /// Use CMPCOV algorithm
    ///
    /// To use this policy, users should first setup [`EDGES_MAP_PTR`][libafl_targets::EDGES_MAP_PTR]
    /// by methods like [`map_shared_memory`][libafl_targets::map_shared_memory].
    Cmpcov,
    /// Do nothing
    None,
}

/// Executor for unicorn afl fuzzing. Can be used in both forkserver mode
/// and LibAFL.
pub struct UnicornAflExecutor<'a, D, OT, H>
where
    D: 'a,
{
    /// The real unicorn engine
    pub uc: Unicorn<'a, UnicornFuzzData<D>>,
    /// The observers, observing each run
    observers: OT,
    /// Whether the `validate_crash_cb` is invoked everytime regardless of
    /// the execution result.
    ///
    /// If false, only execution failure will lead to the callback.
    always_validate: bool,
    /// Stored for deleting hook when dropping
    ///
    /// None if in CMPLOG mode, which does not require coverage feedback
    block_hook: Option<UcHookId>,
    /// Stored for deleting hook when dropping
    ///
    /// None if user does not specify CMPLOG nor CMPCOV
    sub_hook: Option<UcHookId>,
    /// Stored for deleting hook when dropping
    ///
    /// None if user does not specify CMPLOG nor CMPCOV
    cmp_hook: Option<UcHookId>,
    /// Stored for deleting hook when dropping
    ///
    /// None if in infinite persistent mode, which does not TB cache
    new_tb_hook: Option<UcHookId>,
    /// Callback hooks
    callbacks: H,
}

impl<'a, D, OT, H> UnicornAflExecutor<'a, D, OT, H>
where
    D: 'a,
    H: UnicornAflExecutorHook<'a, D>,
{
    /// Create a new executor
    ///
    /// * `always_validate`: Whether call validate callback even if this round does not lead to crash
    /// * `cache_tb`: Whether enable TB-cache, which is useful if not in infinite loop
    pub fn new(
        mut uc: Unicorn<'a, UnicornFuzzData<D>>,
        observers: OT,
        callbacks: H,
        always_validate: bool,
        exits: Vec<u64>,
        cache_tb: bool,
        cmp_policy: CmpPolicy,
    ) -> Result<Self, uc_error> {
        if !exits.is_empty() {
            // Enable exits if requested
            uc.ctl_exits_enable().inspect_err(|ret| {
                warn!("Fail to enable exits due to {ret}");
            })?;
            uc.ctl_set_exits(&exits).inspect_err(|ret| {
                warn!("Fail to write exits due to {ret}");
            })?;
        }

        let block_hook = if matches!(cmp_policy, CmpPolicy::Cmplog) {
            None
        } else {
            trace!("Adding block hook");
            Some(
                uc.add_block_hook(1, 0, |uc, address, size| {
                    hook_code_coverage(uc, address, size);
                })
                .inspect_err(|ret| {
                    warn!("Fail to add block hooks due to {ret}");
                })?,
            )
        };
        let sub_hook;
        let cmp_hook;
        debug!("Our cmp policy is {:?}", &cmp_policy);
        match cmp_policy {
            CmpPolicy::Cmplog => {
                sub_hook = Some(
                    uc.add_tcg_hook(
                        TcgOpCode::SUB,
                        TcgOpFlag::DIRECT,
                        1,
                        0,
                        |uc, address, arg1, arg2, size| {
                            hook_opcode_cmplog(uc, address, arg1, arg2, size);
                        },
                    )
                    .inspect_err(|ret| {
                        warn!("Fail to add sub hooks due to {ret}");
                    })?,
                );
                cmp_hook = Some(
                    uc.add_tcg_hook(
                        TcgOpCode::SUB,
                        TcgOpFlag::CMP,
                        1,
                        0,
                        |uc, address, arg1, arg2, size| {
                            hook_opcode_cmplog(uc, address, arg1, arg2, size);
                        },
                    )
                    .inspect_err(|ret| {
                        warn!("Fail to add cmp hooks due to {ret}");
                    })?,
                );
            }
            CmpPolicy::Cmpcov => {
                sub_hook = Some(
                    uc.add_tcg_hook(
                        TcgOpCode::SUB,
                        TcgOpFlag::DIRECT,
                        1,
                        0,
                        |uc, address, arg1, arg2, size| {
                            hook_opcode_cmpcov(uc, address, arg1, arg2, size);
                        },
                    )
                    .inspect_err(|ret| {
                        warn!("Fail to add sub hooks due to {ret}");
                    })?,
                );
                cmp_hook = Some(
                    uc.add_tcg_hook(
                        TcgOpCode::SUB,
                        TcgOpFlag::CMP,
                        1,
                        0,
                        |uc, address, arg1, arg2, size| {
                            hook_opcode_cmpcov(uc, address, arg1, arg2, size);
                        },
                    )
                    .inspect_err(|ret| {
                        warn!("Fail to add cmp hooks due to {ret}");
                    })?,
                );
            }
            CmpPolicy::None => {
                sub_hook = None;
                cmp_hook = None;
            }
        }
        let new_tb_hook = if cache_tb {
            Some(
                uc.add_edge_gen_hook(1, 0, |uc, cur_tb, _| {
                    if let Some(child_pipe_w) = &uc.get_data_mut().child_pipe_w {
                        if crate::forkserver::write_u32_to_fd(
                            child_pipe_w,
                            crate::forkserver::afl_child_ret::TSL_REQUEST,
                        )
                        .is_err()
                        {
                            error!("Error writing TSL REQUEST");
                            return;
                        }
                        #[expect(clippy::needless_return)]
                        if crate::forkserver::write_u64_to_fd(child_pipe_w, cur_tb.pc).is_err() {
                            error!("Error writing TSL REQUEST pc");
                            return;
                        }
                    }
                })
                .inspect_err(|ret| {
                    warn!("Fail to add edge gen hooks due to {ret}");
                })?,
            )
        } else {
            None
        };

        Ok(Self {
            uc,
            observers,
            callbacks,
            always_validate,
            block_hook,
            sub_hook,
            cmp_hook,
            new_tb_hook,
        })
    }

    /// Bare execution without any state modification. Always call wrappers
    /// like [`run_target`][Executor::run_target] or [`forkserver_run_harness`][crate::harness::forkserver_run_harness]
    pub(crate) fn execute_internal(
        &mut self,
        input: &[u8],
        persistent_round: u64,
    ) -> Result<ExitKind, libafl::Error> {
        self.uc.get_data_mut().clear_prev_loc();

        let accepted = self
            .callbacks
            .place_input(&mut self.uc, input, persistent_round);

        if !accepted {
            trace!("Input not accepted");
            return Ok(ExitKind::Ok);
        }

        let err = self.callbacks.fuzz(&mut self.uc);

        if let Err(err) = &err {
            trace!("Child returns: {err}");
        } else {
            trace!("Child returns: OK");
        }

        let mut crash_found = false;

        if (err.is_err() || self.always_validate)
            && self
                .callbacks
                .validate_crash(&mut self.uc, err, input, persistent_round)
        {
            crash_found = true;
        }

        if crash_found {
            Ok(ExitKind::Crash)
        } else {
            Ok(ExitKind::Ok)
        }
    }
}

impl<D, OT, H> HasObservers for UnicornAflExecutor<'_, D, OT, H> {
    type Observers = OT;

    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}

impl<'a, D, OT, H> Drop for UnicornAflExecutor<'a, D, OT, H>
where
    D: 'a,
{
    fn drop(&mut self) {
        if let Some(block_hook) = self.block_hook.take() {
            if let Err(ret) = self.uc.remove_hook(block_hook) {
                warn!("Fail to uninstall block hook due to {ret}");
            }
        }
        if let Some(sub_hook) = self.sub_hook.take() {
            if let Err(ret) = self.uc.remove_hook(sub_hook) {
                warn!("Fail to uninstall sub tcg opcode hook due to {ret}");
            }
        }
        if let Some(cmp_hook) = self.cmp_hook.take() {
            if let Err(ret) = self.uc.remove_hook(cmp_hook) {
                warn!("Fail to uninstall cmp tcg opcode hook due to {ret}");
            }
        }
        if let Some(new_tb_hook) = self.new_tb_hook.take() {
            if let Err(ret) = self.uc.remove_hook(new_tb_hook) {
                warn!("Fail to uninstall edge gen hook due to {ret}");
            }
        }
    }
}

impl<'a, EM, I, S, Z, D, OT, H> Executor<EM, I, S, Z> for UnicornAflExecutor<'a, D, OT, H>
where
    S: HasExecutions,
    I: HasTargetBytes,
    OT: ObserversTuple<I, S>,
    D: 'a,
    H: UnicornAflExecutorHook<'a, D>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, libafl::Error> {
        *state.executions_mut() += 1;
        self.observers.pre_exec_all(state, input)?;

        let exit_kind = self.execute_internal(&input.target_bytes(), *state.executions())?;

        self.observers.post_exec_all(state, input, &exit_kind)?;

        Ok(exit_kind)
    }
}
