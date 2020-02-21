pub mod arm;
pub mod unicorn_const;
pub mod ffi;

use std::ffi::c_void;
use std::collections::HashMap;
use ffi::{Protection, MemRegion, uc_handle};
use std::pin::Pin;
use std::marker::PhantomPinned;

pub const API_MAJOR: u64 = 1;
pub const API_MINOR: u64 = 0;
pub const VERSION_MAJOR: u64 = 1;
pub const VERSION_MINOR: u64 = 0;
pub const VERSION_EXTRA: u64 = 2;
pub const SECOND_SCALE: u64 = 1000000;
pub const MILISECOND_SCALE: u64 = 1000;

#[derive(Debug)]
pub struct Unicorn<D> {
    inner: Pin<Box<UnicornInner<D>>>
}

#[derive(Debug)]
pub struct UnicornHandle<'a, D> {
    inner: Pin<&'a mut UnicornInner<D>>,
    _pin: PhantomPinned
}

pub struct UnicornInner<D> {
    pub uc: uc_handle,
    pub code_hooks: HashMap<*mut libc::c_void, Box<ffi::CodeHook<D>>>,
    pub data: D
}

impl<D> Unicorn<D> {
    pub fn new(arch: ffi::Arch, mode: ffi::Mode, data: D) -> Result<Unicorn<D>, ffi::Error> {
        let mut handle = std::ptr::null_mut();
        let err = unsafe { ffi::uc_open(arch, mode, &mut handle) };
        if err == ffi::Error::OK {
            Ok(Unicorn {
                inner: Box::pin(UnicornInner {
                uc: handle,
                code_hooks: HashMap::new(),
                data: data
            })})
        } else {
            Err(err)
        }
    }

    pub fn borrow<'a>(&'a mut self) -> UnicornHandle<'a, D> {
        UnicornHandle { inner: self.inner.as_mut(), _pin: std::marker::PhantomPinned }
    }
}

impl<D> UnicornInner<D> {
    pub fn get_data(self: Pin<&mut Self>) -> &mut D {
        unsafe { &mut self.get_unchecked_mut().data }
    }
}
impl<D> std::fmt::Debug for UnicornInner<D> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "Unicorn {{ uc: {:p} }}", self.uc)
    }
}

impl<'a, D> UnicornHandle<'a, D> {
    pub fn get_data(&self) -> &D {
        &self.inner.data
    }

    pub fn get_data_mut(&mut self) -> &mut D {
        unsafe { &mut self.inner.as_mut().get_unchecked_mut().data }
    }

    pub fn mem_regions(&self) -> Result<Vec<MemRegion>, ffi::Error> {
        // We make a copy of the MemRegion structs that are returned by uc_mem_regions()
        // as they have to be freed to the caller. It is simpler to make a copy and free()
        // the originals right away.
        let mut nb_regions: u32 = 0;
        let mut p_regions: *const MemRegion = std::ptr::null_mut();
        let err = unsafe { ffi::uc_mem_regions(self.inner.uc, &mut p_regions, &mut nb_regions) };
        if err == ffi::Error::OK {
            let mut regions = Vec::new();
            for i in 0..nb_regions {
                regions.push(unsafe { std::mem::transmute_copy(&*p_regions.offset(i as isize)) });
            }
            unsafe { libc::free(p_regions as _) };
            Ok(regions)
        } else {
            Err(err)
        }
    }

    pub fn mem_read(&self, address: u64, buf: &mut [u8]) -> Result<(), ffi::Error> {
        let err = unsafe { ffi::uc_mem_read(self.inner.uc, address, buf.as_mut_ptr(), buf.len()) };
        if err == ffi::Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn mem_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), ffi::Error> {
        let err = unsafe { ffi::uc_mem_write(self.inner.uc, address, bytes.as_ptr(), bytes.len()) };
        if err == ffi::Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn mem_map_ptr(&mut self, address: u64, size: usize, perms: Protection, ptr: *mut c_void) -> Result<(), ffi::Error> {
        let err = unsafe { ffi::uc_mem_map_ptr(self.inner.uc, address, size, perms.bits(), ptr) };
        if err == ffi::Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn mem_map(&mut self, address: u64, size: libc::size_t, perms: Protection) -> Result<(), ffi::Error> {
        let err = unsafe { ffi::uc_mem_map(self.inner.uc, address, size, perms.bits()) };
        if err == ffi::Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn reg_write<T: Into<i32>>(&mut self, regid: T, value: u64) -> Result<(), ffi::Error> {
        let err = unsafe { ffi::uc_reg_write(self.inner.uc, regid.into(), &value as *const _ as _) };
        if err == ffi::Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn reg_read<T: Into<i32>>(&self, regid: T) -> Result<u64, ffi::Error> {
        let mut value: u64 = 0;
        let err = unsafe { ffi::uc_reg_read(self.inner.uc, regid.into(), &mut value as *mut u64 as _) };
        if err == ffi::Error::OK {
            Ok(value)
        } else {
            Err(err)
        }
    }

    pub fn reg_read_i32<T: Into<i32>>(&self, regid: T) -> Result<i32, ffi::Error> {
        let mut value: i32 = 0;
        let err = unsafe { ffi::uc_reg_read(self.inner.uc, regid.into(), &mut value as *mut i32 as _) };
        if err == ffi::Error::OK {
            Ok(value)
        } else {
            Err(err)
        }
    }

    pub fn add_code_hook(
        &mut self,
        hook_type: ffi::HookType,
        begin: u64,
        end: u64,
        callback: Box<dyn FnMut(UnicornHandle<D>, u64, u32)>,
    ) -> Result<ffi::uc_hook, ffi::Error>
    {
        let mut hook_ptr = std::ptr::null_mut();
        let mut user_data = Box::new(ffi::CodeHook {
            unicorn: unsafe { self.inner.as_mut().get_unchecked_mut() } as _,
            callback: callback,
        });
        
        let err = unsafe {
            ffi::uc_hook_add(
                self.inner.uc,
                &mut hook_ptr,
                hook_type,
                ffi::code_hook_proxy::<D> as _,
                user_data.as_mut() as *mut _ as _,
                begin,
                end,
            )
        };
        if err == ffi::Error::OK {
            unsafe { self.inner.as_mut().get_unchecked_mut() }.code_hooks.insert(hook_ptr, user_data);
            Ok(hook_ptr)
        } else {
            Err(err)
        }
    }

    pub fn emu_start(&mut self, begin: u64, until: u64, timeout: u64, count: usize) -> Result<(), ffi::Error> {
        let err = unsafe { ffi::uc_emu_start(self.inner.uc, begin, until, timeout, count as _) };
        if err == ffi::Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn emu_stop(&mut self) -> Result<(), ffi::Error> {
        let err = unsafe { ffi::uc_emu_stop(self.inner.uc) };
        if err == ffi::Error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn afl_forkserver_start(&mut self, exits: &[u64]) -> Result<(), ffi::AflRet> {
        let err = unsafe { ffi::uc_afl_forkserver_start(self.inner.uc, exits.as_ptr(), exits.len()) };
        if err == ffi::AflRet::ERROR {
            Err(err)
        } else {
            Ok(())
        }
    }

    pub fn afl_fuzz(&mut self,
            input_file: &str,
            input_placement_callback: Box<dyn FnMut(UnicornHandle<D>, &[u8], i32) -> bool>,
            exits: &[u64],
            crash_validation_callback: Box<dyn FnMut(UnicornHandle<D>, ffi::Error, &[u8], i32) -> bool>,
            always_validate: bool,
            persistent_iters: u32) -> Result<(), ffi::AflRet> {
        let afl_fuzz_callback = Box::pin(ffi::AflFuzzCallback {
            unicorn: unsafe { self.inner.as_mut().get_unchecked_mut() }, 
            input_callback: input_placement_callback,
            validate_callback: crash_validation_callback
        });
        //todo 0-terminated?
    
        let cstyle_input_file = std::ffi::CString::new(input_file).unwrap();
        let err = unsafe { ffi::uc_afl_fuzz(self.inner.uc,
            cstyle_input_file.as_ptr(),
            ffi::input_placement_callback_proxy::<D> as _,
            exits.as_ptr(), exits.len(),
            ffi::crash_validation_callback_proxy::<D> as _,
            always_validate,
            persistent_iters, 
            &*afl_fuzz_callback as *const _ as _) };
        if err == ffi::AflRet::ERROR {
            Err(err)
        } else {
            Ok(())
        }
    }
}
