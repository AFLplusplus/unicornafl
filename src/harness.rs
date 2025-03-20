use libafl::{
    executors::Executor,
    inputs::BytesInput,
    stages::{Restartable, Stage},
    Evaluator,
};
use libafl_targets::{EDGES_MAP_PTR, INPUT_LENGTH_PTR, INPUT_PTR};

#[derive(Debug)]
pub struct LegacyHarnessStage {
    iters: usize,
    map_size: usize,
}

impl LegacyHarnessStage {
    pub fn new(iters: usize, map_size: usize) -> Self {
        Self { iters, map_size }
    }
}

impl<S> Restartable<S> for LegacyHarnessStage {
    fn clear_progress(&mut self, state: &mut S) -> Result<(), libafl::Error> {
        Ok(())
    }

    fn should_restart(&mut self, state: &mut S) -> Result<bool, libafl::Error> {
        Ok(true)
    }
}

impl<E, EM, S, Z> Stage<E, EM, S, Z> for LegacyHarnessStage
where
    E: Executor<EM, BytesInput, S, Z>,
    Z: Evaluator<E, EM, BytesInput, S>,
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
                nix::sys::signal::raise(nix::sys::signal::SIGSTOP).unwrap();
                unsafe {
                    std::ptr::write(EDGES_MAP_PTR, 1);
                }
            }

            // Wrap inputs
            let input = unsafe {
                let len = std::ptr::read(INPUT_LENGTH_PTR);
                BytesInput::new(Vec::from_raw_parts(INPUT_PTR, len as usize, len as usize))
            };

            let (ret, _) = fuzzer.evaluate_filtered(state, executor, manager, &input)?;
            if ret.is_solution() {
                std::process::abort();
            }
        }

        Ok(())
    }
}
