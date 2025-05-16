use std::path::PathBuf;

use libafl::executors::ExitKind;
use libafl_targets::{EDGES_MAP_PTR, INPUT_LENGTH_PTR, INPUT_PTR};
use log::{error, trace};

use crate::{
    executor::{UnicornAflExecutor, UnicornAflExecutorHook},
    forkserver::afl_child_ret::ChildRet,
};

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
    let mut first_pass = true;
    if let Some(iters) = iters {
        for persistent_round in 0..iters {
            let mut child_ret = forkserver_run_harness_once(
                executor,
                &input_path,
                &mut first_pass,
                persistent_round,
            )?;
            if persistent_round == iters - 1 {
                // We are at last round, tell parent we will die
                child_ret = crate::forkserver::afl_child_ret::EXITED;
            }

            trace!("Sending back msg to parent(unicornafl) = {:?}", child_ret);
            if let Some(child_pipe_w) = &executor.uc.get_data().child_pipe_w {
                if crate::forkserver::write_u32_to_fd(child_pipe_w, child_ret).is_err() {
                    error!("[!] Error writing to parent pipe. Parent dead?");
                }
            }
        }
        Ok(())
    } else {
        let mut persistent_round = 0u64;
        loop {
            let child_ret = forkserver_run_harness_once(
                executor,
                &input_path,
                &mut first_pass,
                persistent_round,
            )?;
            persistent_round = persistent_round.wrapping_add(1);
            trace!("Sending back msg to parent(unicornafl) = {:?}", child_ret);
            if let Some(child_pipe_w) = &executor.uc.get_data().child_pipe_w {
                if crate::forkserver::write_u32_to_fd(child_pipe_w, child_ret).is_err() {
                    error!("[!] Error writing to parent pipe. Parent dead?");
                }
            }
        }
    }
}

/// If this returns `Err`, this means there are something fatal happened in
/// execution, this means the loop cannot proceed.
fn forkserver_run_harness_once<'a, D, OT, H>(
    executor: &mut UnicornAflExecutor<'a, D, OT, H>,
    input_path: &Option<PathBuf>,
    first_pass: &mut bool,
    persistent_round: u64,
) -> Result<ChildRet, libafl::Error>
where
    D: 'a,
    H: UnicornAflExecutorHook<'a, D>,
{
    if *first_pass {
        *first_pass = false;
    } else if let Some(parent_pipe_r) = &executor.uc.get_data().parent_pipe_r {
        if crate::forkserver::read_u32_from_fd(parent_pipe_r).is_err() {
            error!("[!] Error reading from parent pipe. Parent dead?");
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
        crate::forkserver::afl_child_ret::NEXT
    } else {
        crate::forkserver::afl_child_ret::FOUND_CRASH
    };

    Ok(msg)
}
