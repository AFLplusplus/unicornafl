use std::path::PathBuf;

use libafl::executors::ExitKind;
use libafl_targets::{EDGES_MAP_PTR, INPUT_LENGTH_PTR, INPUT_PTR};
use log::{error, trace};

use crate::executor::{UnicornAflExecutor, UnicornAflExecutorHook};

/// Harness loop for forkserver mode
pub fn forkserver_run_harness<'a, D, OT, H>(
    executor: &mut UnicornAflExecutor<'a, D, OT, H>,
    input_path: Option<PathBuf>,
    iters: Option<u64>,
) -> Result<(), libafl::Error>
where
    D: 'a,
    H: UnicornAflExecutorHook<'a, D>,
{
    if let Some(iters) = iters {
        for persistent_round in 0..iters {
            forkserver_run_harness_once(
                executor,
                &input_path,
                persistent_round == 0,
                persistent_round == iters - 1,
                persistent_round,
            )?;
        }
        Ok(())
    } else {
        let mut persistent_round = 0u64;
        let mut is_first_pass = true;
        loop {
            forkserver_run_harness_once(
                executor,
                &input_path,
                is_first_pass,
                false,
                persistent_round,
            )?;
            is_first_pass = false;
            persistent_round = persistent_round.wrapping_add(1);
        }
    }
}

/// If this returns `Err`, this means there are something fatal happened in
/// execution, this means the loop cannot proceed.
fn forkserver_run_harness_once<'a, D, OT, H>(
    executor: &mut UnicornAflExecutor<'a, D, OT, H>,
    input_path: &Option<PathBuf>,
    is_first_pass: bool,
    is_last_pass: bool,
    persistent_round: u64,
) -> Result<(), libafl::Error>
where
    D: 'a,
    H: UnicornAflExecutorHook<'a, D>,
{
    if !is_first_pass {
        if let Some(parent_pipe_r) = &executor.uc.get_data().parent_pipe_r {
            if crate::forkserver::read_u32_from_fd(parent_pipe_r).is_err() {
                error!("[!] Error reading from parent pipe. Parent dead?");
            }
        }
    }
    unsafe {
        std::ptr::write_bytes(EDGES_MAP_PTR, 0, executor.uc.get_data().map_size() as usize);
        std::ptr::write_volatile(EDGES_MAP_PTR, 1);
    }

    let input_str;
    let input = if let Some(input) = input_path.as_ref() {
        input_str = std::fs::read(input)?;
        input_str.as_slice()
    } else if unsafe { !INPUT_PTR.is_null() && !INPUT_LENGTH_PTR.is_null() } {
        unsafe { std::slice::from_raw_parts(INPUT_PTR, (*INPUT_LENGTH_PTR) as usize) }
    } else {
        return Err(libafl::Error::empty("no input given"));
    };

    let exit_kind = executor.execute_internal(input, persistent_round)?;
    let msg = if matches!(exit_kind, ExitKind::Ok) {
        if is_last_pass {
            // We are at last round, tell parent we will die
            crate::forkserver::afl_child_ret::EXITED
        } else {
            crate::forkserver::afl_child_ret::NEXT
        }
    } else if is_last_pass {
        // We are at last round, tell parent we will die
        crate::forkserver::afl_child_ret::FOUND_CRASH_AND_EXITED
    } else {
        crate::forkserver::afl_child_ret::FOUND_CRASH
    };
    trace!("Sending back msg to parent(unicornafl) = {msg:?}");
    if let Some(child_pipe_w) = &executor.uc.get_data().child_pipe_w {
        if crate::forkserver::write_u32_to_fd(child_pipe_w, msg).is_err() {
            error!("[!] Error writing to parent pipe. Parent dead?");
        }
    }

    Ok(())
}
