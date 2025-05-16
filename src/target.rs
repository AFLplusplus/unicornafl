use std::path::PathBuf;

use libafl_targets::{__afl_map_size, EDGES_MAP_PTR, SHM_FUZZING, cmps::CMPLOG_ENABLED};
use log::{debug, error, trace, warn};
use unicorn_engine::{Arch, RegisterARM, Unicorn, uc_error};

use crate::{
    executor::{CmpPolicy, UnicornAflExecutor, UnicornAflExecutorHook, UnicornFuzzData},
    uc_afl_ret,
};

/// Dummy fuzz callback if user don't specify their own callback
pub fn dummy_uc_fuzz_callback<'a, D: 'a>(
    uc: &mut Unicorn<'a, UnicornFuzzData<D>>,
) -> Result<(), uc_error> {
    let arch = uc.get_arch();

    let mut pc = uc.pc_read()?;
    if arch == Arch::ARM {
        let cpsr = uc.reg_read(RegisterARM::CPSR)?;
        if cpsr & 0x20 != 0 {
            pc |= 1;
        }
    }

    uc.emu_start(pc, 0, 0, 0)
}

/// Dummy crash validation callback if user don't specify their own callback
pub fn dummy_uc_validate_crash_callback<'a, D: 'a>(
    _uc: &mut Unicorn<'a, UnicornFuzzData<D>>,
    unicorn_result: Result<(), uc_error>,
    _input: &[u8],
    _persistent_round: u64,
) -> bool {
    unicorn_result.is_err()
}

/// Internal entrypoint for fuzzing.
///
/// This is only expected to be runned in forkserver mode.
pub fn child_fuzz<'a, D: 'a>(
    uc: Unicorn<'a, UnicornFuzzData<D>>,
    input_file: Option<PathBuf>,
    iters: Option<u64>,
    callbacks: impl UnicornAflExecutorHook<'a, D>,
    exits: Vec<u64>,
    always_validate: bool,
    run_once_if_no_afl_present: bool,
) -> Result<(), uc_afl_ret> {
    // Enable logging
    #[cfg(feature = "env_logger")]
    env_logger::init();

    let has_afl = libafl_targets::map_input_shared_memory().is_ok()
        && libafl_targets::map_shared_memory().is_ok();

    trace!("AFL detected: {has_afl}");
    if input_file.is_some() && has_afl {
        warn!("Shared memory fuzzing is enabled and the input file is ignored!");
    }
    if input_file.is_none() && !has_afl {
        warn!("No input file is provided. We will run harness with zero inputs.");
    }
    let mut local_map;
    if !has_afl && run_once_if_no_afl_present {
        let map_size = uc.get_data().map_size();
        // This local variable will never be freed until current function is end, which
        // is after the forkserver loop.
        local_map = vec![0u8; map_size as usize];
        unsafe { EDGES_MAP_PTR = local_map.as_mut_ptr() }
        // If no afl, input will be read from input_file in forkserver_run_harness,
        // thus no need to setup INPUT_PTR and INPUT_LENGTH_PTR
    }
    if has_afl || run_once_if_no_afl_present {
        let map_size = uc.get_data().map_size();
        unsafe {
            __afl_map_size = map_size as usize;
            SHM_FUZZING = 1;
        }
        debug!("Map size is: {map_size}");

        // The following code will handle CMPLOG and CMPCOV envs
        //
        // In AFL++, the cmplog shared memory id env will always set if
        // users specify "-c" option to `afl-fuzz` in commandline, no
        // matter whether it is invoking the cmplog_binary or normal binary. See
        // https://github.com/AFLplusplus/AFLplusplus/blob/c340a022e2546488c15f85593d0f37e30eeaab3a/src/afl-sharedmem.c#L321
        //
        // But only for cmplog binaries, AFL++ will set ___AFL_EINS_ZWEI_POLIZEI___, see
        // https://github.com/AFLplusplus/AFLplusplus/blob/c340a022e2546488c15f85593d0f37e30eeaab3a/src/afl-fuzz-cmplog.c#L34
        //
        // As a result, we check both env vars, and users can pass the same unicornafl
        // binary as both normal binary and cmplog binary (use `-c 0` in `afl-fuzz` cmdline).
        //
        // The `CMPLOG_ENABLED` controls whether the underlined `__libafl_targets_cmplog_instructions`
        // will take effect.
        let cmp_policy;
        let has_cmplog = std::env::var("___AFL_EINS_ZWEI_POLIZEI___").is_ok()
            && libafl_targets::map_cmplog_shared_memory().is_ok();
        let has_cmpcov = std::env::var("UNICORN_AFL_CMPCOV").is_ok();
        if has_cmplog {
            if has_cmpcov {
                warn!("CMPLOG and CMPCOV turned on at the same time!");
                warn!("I'll turn off CMPCOV.");
            }
            unsafe {
                CMPLOG_ENABLED = 1;
            }
            cmp_policy = CmpPolicy::Cmplog;
        } else if has_cmpcov {
            cmp_policy = CmpPolicy::Cmpcov;
        } else {
            cmp_policy = CmpPolicy::None;
        }

        let iters = if !has_afl && run_once_if_no_afl_present {
            Some(1)
        } else {
            iters
        };

        let executor = UnicornAflExecutor::new(
            uc,
            (),
            callbacks,
            always_validate,
            exits,
            iters.is_some(),
            cmp_policy,
        )?;
        let mut forkserver_parent = crate::forkserver::UnicornAflForkserverParent::new(executor);
        libafl_targets::start_forkserver(&mut forkserver_parent)?;
        let mut executor = forkserver_parent.executor;
        let input_file = if has_afl { None } else { input_file };
        if let Err(e) = crate::harness::forkserver_run_harness(&mut executor, input_file, iters) {
            // The error cannot be propagated since we are in child process now.
            // So just log.
            error!("Fuzzing fails with error from libafl: {e}");
        }
    } else {
        // TODO: Run with libafl directly
    }
    Ok(())
}
