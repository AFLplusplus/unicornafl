use std::{ffi::CString, path::PathBuf};

use libafl::{
    executors::Executor,
    stages::{Restartable, Stage},
    Evaluator,
};
use libafl_bolts::ownedref::OwnedSlice;
use libafl_targets::{EDGES_MAP_PTR, INPUT_LENGTH_PTR, INPUT_PTR};
use nix::{
    libc::{mmap64, open, MAP_PRIVATE, O_RDONLY, PROT_READ, PROT_WRITE},
    sys::stat::fstat,
};

use crate::executor::UnsafeSliceInput;

#[derive(Debug)]
pub struct LegacyHarnessStage {
    iters: usize,
    map_size: usize,
    input_str: Option<PathBuf>,
}

impl LegacyHarnessStage {
    pub fn new(iters: usize, map_size: usize, input_str: Option<PathBuf>) -> Self {
        Self {
            iters,
            map_size,
            input_str,
        }
    }
}

impl<S> Restartable<S> for LegacyHarnessStage {
    fn clear_progress(&mut self, _state: &mut S) -> Result<(), libafl::Error> {
        Ok(())
    }

    fn should_restart(&mut self, _state: &mut S) -> Result<bool, libafl::Error> {
        Ok(true)
    }
}

impl<'a, E, EM, S, Z> Stage<E, EM, S, Z> for LegacyHarnessStage
where
    E: Executor<EM, UnsafeSliceInput<'a>, S, Z>,
    Z: Evaluator<E, EM, UnsafeSliceInput<'a>, S>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), libafl::Error> {
        let mut first_pass = true;
        for _ in 0..self.iters {
            // taken from __afl_persistent_loop
            if first_pass {
                first_pass = false;
                unsafe {
                    std::ptr::write_bytes(EDGES_MAP_PTR, 0, self.map_size);
                    std::ptr::write(EDGES_MAP_PTR, 1);
                }
            } else {
                // Waiting for next input
                if self.input_str.is_none() {
                    nix::sys::signal::raise(nix::sys::signal::SIGSTOP).unwrap();
                    unsafe {
                        std::ptr::write(EDGES_MAP_PTR, 1);
                    }
                }
            }

            // Wrap inputs
            let input = if let Some(input) = self.input_str.as_ref() {
                unsafe {
                    let fpath =
                        CString::new(input.to_str().ok_or(libafl::Error::invalid_corpus(
                            format!("invalid path {:?}", input.as_os_str()),
                        ))?)
                        .unwrap(); // to_str has checked so
                    let fd = open(fpath.as_ptr(), O_RDONLY);
                    if fd == -1 {
                        return Err(libafl::Error::invalid_corpus(format!(
                            "invalid path {:?}",
                            input.as_os_str()
                        )));
                    }

                    let stat = fstat(fd).map_err(|e| libafl::Error::unknown(e.to_string()))?;
                    let ptr = mmap64(
                        std::ptr::null_mut(),
                        stat.st_size as usize,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE,
                        fd,
                        0,
                    );
                    if ptr.is_null() {
                        return Err(libafl::Error::illegal_state("mmap"));
                    }

                    UnsafeSliceInput {
                        input: OwnedSlice::from_raw_parts(ptr as _, stat.st_size as usize),
                    }
                }
            } else {
                UnsafeSliceInput {
                    input: unsafe {
                        OwnedSlice::from_raw_parts(INPUT_PTR, (*INPUT_LENGTH_PTR) as usize)
                    },
                }
            };

            let (ret, _) = fuzzer.evaluate_filtered(state, executor, manager, &input)?;
            if ret.is_solution() {
                std::process::abort();
            }
        }

        Ok(())
    }
}
