use std::path::PathBuf;

use libafl::{
    corpus::{Corpus, InMemoryCorpus, Testcase},
    events::SimpleEventManager,
    feedbacks::{BoolValueFeedback, CrashFeedback},
    monitors::SimpleMonitor,
    schedulers::QueueScheduler,
    state::StdState,
    Fuzzer, StdFuzzer,
};
use libafl_bolts::{
    ownedref::OwnedSlice,
    rands::StdRand,
    tuples::{tuple_list, Handle},
};
use libafl_targets::{EDGES_MAP_SIZE, SHM_FUZZING};
use log::{debug, trace, warn};
use unicorn_engine::{uc_error, Arch, RegisterARM, Unicorn};

use crate::{
    executor::{UnicornAflExecutor, UnicornFuzzData, UnsafeSliceInput},
    harness::LegacyHarnessStage,
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
        if cpsr & 0x20 == 1 {
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

/// Internal entrypoint for fuzzing
pub fn child_fuzz<'a, D: 'a>(
    uc: Unicorn<'a, UnicornFuzzData<D>>,
    input_file: Option<PathBuf>,
    iters: u32,
    place_input_cb: impl FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>, &[u8], u64) -> bool + 'a,
    validate_crash_cb: impl FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>, Result<(), uc_error>, &[u8], u64) -> bool
        + 'a,
    fuzz_callback: impl FnMut(&mut Unicorn<'a, UnicornFuzzData<D>>) -> Result<(), uc_error> + 'a,
    exits: Vec<u64>,
    always_validate: bool,
    run_once_if_no_afl_present: bool,
) -> Result<(), uc_afl_ret> {
    // Enable logging
    #[cfg(feature = "env_logger")]
    env_logger::init();

    let has_afl = libafl_targets::map_input_shared_memory() && libafl_targets::map_shared_memory();

    trace!("AFL detected: {}", has_afl);
    if !input_file.is_none() && has_afl {
        warn!("Shared memory fuzzing is enabled and the input file is ignored!");
    }
    if input_file.is_none() && !has_afl {
        warn!("No input file is provided. We will run harness with zero inputs.");
    }
    if has_afl || run_once_if_no_afl_present {
        let map_size = uc.get_data().map_size();
        unsafe {
            EDGES_MAP_SIZE = map_size as usize;
            SHM_FUZZING = 1;
        }
        libafl_targets::start_forkserver();
        // Only child returns here
        let map_size = unsafe { EDGES_MAP_SIZE };
        debug!("Map size is: {}", map_size);
        let mut executor = UnicornAflExecutor::new(
            uc,
            place_input_cb,
            validate_crash_cb,
            fuzz_callback,
            always_validate,
            exits,
        )?;

        let mut fb = BoolValueFeedback::new(&Handle::new("dumb_ob".into()));
        let mut sol = CrashFeedback::new();
        let mut corpus = InMemoryCorpus::new();
        corpus.add(Testcase::new(UnsafeSliceInput {
            input: OwnedSlice::from(Vec::<u8>::new()),
        }))?;
        let mut state = StdState::new(
            StdRand::new(),
            corpus,
            InMemoryCorpus::new(),
            &mut fb,
            &mut sol,
        )?;

        let mut mgr = SimpleEventManager::new(SimpleMonitor::new(|s| {
            debug!("{}", s);
        }));
        let sched = QueueScheduler::new();
        let iters = if run_once_if_no_afl_present { 1 } else { iters };
        let input_file = if has_afl { None } else { input_file };
        let stage = LegacyHarnessStage::new(iters as usize, map_size, input_file);
        let mut stages = tuple_list!(stage);
        let mut fuzzer = StdFuzzer::new(sched, fb, sol);

        if let Err(e) = fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr) {
            warn!("Fuzzing fails with error from libafl: {}", e);
        }
    } else {
        // Run with libafl directly
    }
    Ok(())
}
