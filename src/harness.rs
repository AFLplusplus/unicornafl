use std::path::PathBuf;

use libafl::executors::ExitKind;
use libafl_targets::{EDGES_MAP_PTR, INPUT_LENGTH_PTR, INPUT_PTR};
use log::error;

use crate::executor::{UnicornAflExecutor, UnicornAflExecutorHook};

/// Harness loop for forkserver mode
pub fn forkserver_run_harness<'a, D, OT, H>(
    executor: &mut UnicornAflExecutor<'a, D, OT, H>,
    input_path: Option<PathBuf>,
    iters: usize,
) -> Result<(), libafl::Error>
where
    D: 'a,
    H: UnicornAflExecutorHook<'a, D>,
{
    let mut first_pass = true;
    for execution_round in 0..iters {
        if first_pass {
            first_pass = false;
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
        } else {
            unsafe { std::slice::from_raw_parts(INPUT_PTR, (*INPUT_LENGTH_PTR) as usize) }
        };

        let exit_kind = executor.execute_internal(input, execution_round as u64)?;

        let msg = if matches!(exit_kind, ExitKind::Ok) {
            crate::forkserver::afl_child_ret::NEXT
        } else {
            crate::forkserver::afl_child_ret::FOUND_CRASH
        };
        if let Some(child_pipe_w) = &executor.uc.get_data().child_pipe_w {
            if crate::forkserver::write_u32_to_fd(child_pipe_w, msg).is_err() {
                error!("[!] Error writing to parent pipe. Parent dead?");
            }
        }
    }

    Ok(())
}
