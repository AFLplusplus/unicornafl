use std::{
    ffi::{c_char, CStr},
    os::raw::c_void,
    path::PathBuf,
};

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
use unicorn_engine::{
    ffi::{uc_ctl, uc_emu_start, uc_handle, uc_reg_read},
    uc_error, Arch, ControlType, Mode, RegisterARM, RegisterARM64, RegisterM68K, RegisterMIPS,
    RegisterPPC, RegisterRISCV, RegisterS390X, RegisterSPARC, RegisterTRICORE, RegisterX86,
};

use crate::{
    executor::{UnicornAflExecutor, UnsafeSliceInput},
    harness::LegacyHarnessStage,
    uc_afl_cb_place_input_t, uc_afl_cb_validate_crash_t, uc_afl_fuzz_cb_t, uc_afl_ret,
};

fn get_afl_map_size() -> u32 {
    std::env::var("AFL_MAP_SIZE")
        .ok()
        .map(|sz| u32::from_str_radix(&sz, 10).ok())
        .flatten()
        .unwrap_or(1 << 16) // MAP_SIZE
}

#[no_mangle]
extern "C" fn dummy_uc_fuzz_callback(uc: uc_handle, _data: *mut c_void) -> uc_error {
    let mut arch = 0i32;
    let ret = unsafe {
        uc_ctl(
            uc,
            ControlType::UC_CTL_UC_ARCH as u32 | ControlType::UC_CTL_IO_READ as u32,
            &mut arch,
        )
    };
    if ret != uc_error::OK {
        return ret;
    }

    let mut mode = 0i32;
    let ret = unsafe {
        uc_ctl(
            uc,
            ControlType::UC_CTL_UC_MODE as u32 | ControlType::UC_CTL_IO_READ as u32,
            &mut mode,
        )
    };
    if ret != uc_error::OK {
        return ret;
    }

    let mut pc = 0u64;
    let ret = if arch == Arch::X86 as i32 {
        if mode == Mode::MODE_32.bits() {
            unsafe { uc_reg_read(uc, RegisterX86::EIP as i32, &mut pc as *mut u64 as _) }
        } else if mode == Mode::MODE_16.bits() {
            unsafe { uc_reg_read(uc, RegisterX86::IP as i32, &mut pc as *mut u64 as _) }
        } else {
            unsafe { uc_reg_read(uc, RegisterX86::RIP as i32, &mut pc as *mut u64 as _) }
        }
    } else if arch == Arch::ARM as i32 {
        let mut cpsr = 0u64;
        let ret = unsafe { uc_reg_read(uc, RegisterARM::CPSR as i32, &mut cpsr as *mut u64 as _) };
        if ret != uc_error::OK {
            return ret;
        }
        let ret = unsafe { uc_reg_read(uc, RegisterARM::PC as i32, &mut pc as *mut u64 as _) };
        if cpsr & 0x20 == 1 {
            pc |= 1;
        }
        ret
    } else if arch == Arch::RISCV as i32 {
        unsafe { uc_reg_read(uc, RegisterRISCV::PC as i32, &mut pc as *mut u64 as _) }
    } else if arch == Arch::MIPS as i32 {
        unsafe { uc_reg_read(uc, RegisterMIPS::PC as i32, &mut pc as *mut u64 as _) }
    } else if arch == Arch::PPC as i32 {
        unsafe { uc_reg_read(uc, RegisterPPC::PC as i32, &mut pc as *mut u64 as _) }
    } else if arch == Arch::SPARC as i32 {
        unsafe { uc_reg_read(uc, RegisterSPARC::PC as i32, &mut pc as *mut u64 as _) }
    } else if arch == Arch::M68K as i32 {
        unsafe { uc_reg_read(uc, RegisterM68K::PC as i32, &mut pc as *mut u64 as _) }
    } else if arch == Arch::S390X as i32 {
        unsafe { uc_reg_read(uc, RegisterS390X::PC as i32, &mut pc as *mut u64 as _) }
    } else if arch == Arch::ARM64 as i32 {
        unsafe { uc_reg_read(uc, RegisterARM64::PC as i32, &mut pc as *mut u64 as _) }
    } else if arch == Arch::TRICORE as i32 {
        unsafe { uc_reg_read(uc, RegisterTRICORE::PC as i32, &mut pc as *mut u64 as _) }
    } else {
        uc_error::ARCH
    };

    if ret != uc_error::OK {
        return ret;
    }

    unsafe { uc_emu_start(uc, pc, 0, 0, 0) }
}

pub fn child_fuzz(
    uc: uc_handle,
    input_file: *const c_char,
    iters: u32,
    place_input_cb: uc_afl_cb_place_input_t,
    validate_crash_cb: Option<uc_afl_cb_validate_crash_t>,
    exits: Vec<u64>,
    fuzz_callback: Option<uc_afl_fuzz_cb_t>,
    always_validate: bool,
    run_once_if_no_afl_present: bool,
    data: *mut c_void,
) -> Result<(), uc_afl_ret> {
    // Enable logging
    #[cfg(feature = "env_logger")]
    env_logger::init();

    let has_afl = libafl_targets::map_input_shared_memory() && libafl_targets::map_shared_memory();

    trace!("AFL detected: {}", has_afl);
    if !input_file.is_null() && has_afl {
        warn!("Shared memory fuzzing is enabled and the input file is ignored!");
    }
    if has_afl || run_once_if_no_afl_present {
        let map_size = get_afl_map_size();
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
            fuzz_callback.unwrap_or(dummy_uc_fuzz_callback),
            always_validate,
            exits,
            map_size as u32,
            data,
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
        let input_file = if has_afl {
            None
        } else {
            if input_file.is_null() {
                None
            } else {
                // legact usage
                Some(PathBuf::from(
                    unsafe { CStr::from_ptr(input_file) }
                        .to_str()
                        .map_err(|_| uc_afl_ret::UC_AFL_RET_FFI)?,
                ))
            }
        };
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
