use std::convert::Infallible;

use nix::libc::uintptr_t;
use pyo3::{
    Bound, IntoPyObject, PyResult, pyfunction, pymodule,
    types::{PyInt, PyModule, PyModuleMethods},
    wrap_pyfunction,
};

use crate::uc_afl_ret;

impl<'py> IntoPyObject<'py> for uc_afl_ret {
    type Target = PyInt;
    type Output = Bound<'py, Self::Target>;
    type Error = Infallible;

    fn into_pyobject(self, py: pyo3::Python<'py>) -> Result<Self::Output, Self::Error> {
        u64::into_pyobject(self as _, py)
    }
}

#[pyfunction]
pub fn uc_afl_fuzz(
    uc_handle: uintptr_t,
    input_file: uintptr_t,
    place_input_callback: uintptr_t,
    exits: uintptr_t,
    exit_count: usize,
    validate_crash_callback: Option<uintptr_t>, // will non-ffi safe with pyfunction and extern "C"
    always_validate: bool,
    persistent_iters: u64,
    data: uintptr_t,
) -> uc_afl_ret {
    crate::uc_afl_fuzz(
        uc_handle as _,
        input_file as _,
        unsafe { std::mem::transmute(place_input_callback) },
        exits as _,
        exit_count,
        unsafe { validate_crash_callback.map(|t| std::mem::transmute(t)) },
        always_validate,
        persistent_iters,
        data as _,
    )
}

#[pyfunction]
pub fn uc_afl_fuzz_custom(
    uc_handle: uintptr_t,
    input_file: uintptr_t,
    place_input_callback: uintptr_t,
    fuzz_callback: uintptr_t,
    validate_crash_callback: Option<uintptr_t>,
    always_validate: bool,
    persistent_iters: u64,
    data: uintptr_t,
) -> uc_afl_ret {
    crate::uc_afl_fuzz_custom(
        uc_handle as _,
        input_file as _,
        unsafe { std::mem::transmute(place_input_callback) },
        unsafe { std::mem::transmute(fuzz_callback) },
        unsafe { validate_crash_callback.map(|t| std::mem::transmute(t)) },
        always_validate,
        persistent_iters,
        data as _,
    )
}

#[pymodule]
fn unicornafl(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(uc_afl_fuzz, m)?)?;
    m.add_function(wrap_pyfunction!(uc_afl_fuzz_custom, m)?)?;
    m.add("UC_AFL_RET_OK", uc_afl_ret::UC_AFL_RET_OK as i32)?;
    m.add("UC_AFL_RET_ERROR", uc_afl_ret::UC_AFL_RET_ERROR as i32)?;
    m.add("UC_AFL_RET_CHILD", uc_afl_ret::UC_AFL_RET_CHILD as i32)?;
    m.add("UC_AFL_RET_NO_AFL", uc_afl_ret::UC_AFL_RET_NO_AFL as i32)?;
    m.add(
        "UC_AFL_RET_CALLED_TWICE",
        uc_afl_ret::UC_AFL_RET_CALLED_TWICE as i32,
    )?;
    m.add(
        "UC_AFL_RET_FINISHED",
        uc_afl_ret::UC_AFL_RET_FINISHED as i32,
    )?;
    m.add(
        "UC_AFL_RET_INVALID_UC",
        uc_afl_ret::UC_AFL_RET_INVALID_UC as i32,
    )?;
    m.add("UC_AFL_RET_UC_ERR", uc_afl_ret::UC_AFL_RET_UC_ERR as i32)?;
    m.add("UC_AFL_RET_LIBAFL", uc_afl_ret::UC_AFL_RET_LIBAFL as i32)?;
    m.add("UC_AFL_RET_FFI", uc_afl_ret::UC_AFL_RET_FFI as i32)?;
    Ok(())
}
