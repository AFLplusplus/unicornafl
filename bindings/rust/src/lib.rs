pub mod arm;
pub mod arm64;
pub mod x86;
pub mod sparc;
pub mod mips;
pub mod m68k;
pub mod ucconst;
mod ffi;
pub mod utils;

use std::ffi::c_void;
use std::collections::HashMap;
use ucconst::{Protection, MemRegion};
use ffi::uc_handle;
use std::pin::Pin;
use std::marker::PhantomPinned;

#[derive(Debug)]
pub struct Context {
    context: ffi::uc_context,
}

impl Context {
    pub fn new() -> Self {
        Context { context: 0 }
    }
    pub fn is_initialized(&self) -> bool {
        self.context != 0
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { ffi::uc_free(self.context) };
    }
}

#[derive(Debug)]
pub struct Unicorn<D> {
    inner: Pin<Box<UnicornInner<D>>>
}

#[derive(Debug)]
pub struct UnicornHandle<'a, D> {
    inner: Pin<&'a mut UnicornInner<D>>
}

pub struct UnicornInner<D> {
    pub uc: uc_handle,
    pub arch: ucconst::Arch,
    pub code_hooks: HashMap<*mut libc::c_void, Box<ffi::CodeHook<D>>>,
    pub mem_hooks: HashMap<*mut libc::c_void, Box<ffi::MemHook<D>>>,
    pub intr_hooks: HashMap<*mut libc::c_void, Box<ffi::InterruptHook<D>>>,
    pub ins_hooks: HashMap<*mut libc::c_void, Box<ffi::InstructionHook<D>>>,
    pub data: D,
    _pin: PhantomPinned
}

impl<D> Unicorn<D> {
    pub fn new(arch: ucconst::Arch, mode: ucconst::Mode, data: D) -> Result<Unicorn<D>, ucconst::uc_error> {
        let mut handle = std::ptr::null_mut();
        let err = unsafe { ffi::uc_open(arch, mode, &mut handle) };
        if err == ucconst::uc_error::OK {
            Ok(Unicorn {
                inner: Box::pin(UnicornInner {
                uc: handle,
                arch: arch,
                code_hooks: HashMap::new(),
                mem_hooks: HashMap::new(),
                intr_hooks: HashMap::new(),
                ins_hooks: HashMap::new(),
                data: data,
                _pin: std::marker::PhantomPinned
            })})
        } else {
            Err(err)
        }
    }

    pub fn borrow<'a>(&'a mut self) -> UnicornHandle<'a, D> {
        UnicornHandle { inner: self.inner.as_mut() }
    }
}

impl<D> Drop for Unicorn<D> {
    fn drop(&mut self) {
        unsafe { ffi::uc_close(self.inner.uc) };
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

    pub fn get_arch(&self) -> ucconst::Arch {
        self.inner.arch
    }

    pub fn mem_regions(&self) -> Result<Vec<MemRegion>, ucconst::uc_error> {
        let mut nb_regions: u32 = 0;
        let mut p_regions: *const MemRegion = std::ptr::null_mut();
        let err = unsafe { ffi::uc_mem_regions(self.inner.uc, &mut p_regions, &mut nb_regions) };
        if err == ucconst::uc_error::OK {
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

    pub fn mem_read(&self, address: u64, buf: &mut [u8]) -> Result<(), ucconst::uc_error> {
        let err = unsafe { ffi::uc_mem_read(self.inner.uc, address, buf.as_mut_ptr(), buf.len()) };
        if err == ucconst::uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn mem_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), ucconst::uc_error> {
        let err = unsafe { ffi::uc_mem_write(self.inner.uc, address, bytes.as_ptr(), bytes.len()) };
        if err == ucconst::uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn mem_map_ptr(&mut self, address: u64, size: usize, perms: Protection, ptr: *mut c_void) -> Result<(), ucconst::uc_error> {
        let err = unsafe { ffi::uc_mem_map_ptr(self.inner.uc, address, size, perms.bits(), ptr) };
        if err == ucconst::uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn mem_map(&mut self, address: u64, size: libc::size_t, perms: Protection) -> Result<(), ucconst::uc_error> {
        let err = unsafe { ffi::uc_mem_map(self.inner.uc, address, size, perms.bits()) };
        if err == ucconst::uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn mem_unmap(&mut self, address: u64, size: libc::size_t) -> Result<(), ucconst::uc_error> {
        let err = unsafe { ffi::uc_mem_unmap(self.inner.uc, address, size) };
        if err == ucconst::uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }


    pub fn mem_protect(&mut self, address: u64, size: libc::size_t, perms: Protection) -> Result<(), ucconst::uc_error> {
        let err = unsafe { ffi::uc_mem_protect(self.inner.uc, address, size, perms.bits()) };
        if err == ucconst::uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    // Write an unsigned value from a register.
    // 
    // Not to be used with registers larger than 64 bit.
    pub fn reg_write<T: Into<i32>>(&mut self, regid: T, value: u64) -> Result<(), ucconst::uc_error> {
        let err = unsafe { ffi::uc_reg_write(self.inner.uc, regid.into(), &value as *const _ as _) };
        if err == ucconst::uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    // Write variable sized values into registers.
    // 
    // The user has to make sure that the buffer length matches the register size.
    // This adds support for registers >64 bit (GDTR/IDTR, XMM, YMM, ZMM (x86); Q, V (arm64)).
    pub fn reg_write_long<T: Into<i32>>(&self, regid: T, value: Box<[u8]>) -> Result<(), ucconst::uc_error> {
        let err = unsafe { ffi::uc_reg_write(self.inner.uc, regid.into(), value.as_ptr() as _) };
        if err == ucconst::uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    // Read an unsigned value from a register.
    // 
    // Not to be used with registers larger than 64 bit.
    pub fn reg_read<T: Into<i32>>(&self, regid: T) -> Result<u64, ucconst::uc_error> {
        let mut value: u64 = 0;
        let err = unsafe { ffi::uc_reg_read(self.inner.uc, regid.into(), &mut value as *mut u64 as _) };
        if err == ucconst::uc_error::OK {
            Ok(value)
        } else {
            Err(err)
        }
    }

    // Read 128, 256 or 512 bit register value into heap allocated byte array.
    // 
    // This adds safe support for registers >64 bit (GDTR/IDTR, XMM, YMM, ZMM (x86); Q, V (arm64)).
    pub fn reg_read_long<T: Into<i32>>(&self, regid: T) -> Result<Box<[u8]>, ucconst::uc_error> {
        let err: ucconst::uc_error;
        let boxed: Box<[u8]>;
        let mut value: Vec<u8>;
        let curr_reg_id = regid.into();
        let curr_arch = self.get_arch();

        if curr_arch == ucconst::Arch::X86 {
            if curr_reg_id >= x86::RegisterX86::XMM0 as i32 && curr_reg_id <= x86::RegisterX86::XMM31 as i32 {
                value = vec![0; 16 as usize];                
            } else if curr_reg_id >= x86::RegisterX86::YMM0 as i32 && curr_reg_id <= x86::RegisterX86::YMM31 as i32 {
                value = vec![0; 32 as usize];
            } else if curr_reg_id >= x86::RegisterX86::ZMM0 as i32 && curr_reg_id <= x86::RegisterX86::ZMM31 as i32 {
                value = vec![0; 64 as usize];
            } else if curr_reg_id == x86::RegisterX86::GDTR as i32 ||
                      curr_reg_id == x86::RegisterX86::IDTR as i32 {
                value = vec![0; 10 as usize]; // 64 bit base address in IA-32e mode
            } else {
                return Err(ucconst::uc_error::ARG)
            }
        } else if curr_arch == ucconst::Arch::ARM64 {
            if (curr_reg_id >= arm64::RegisterARM64::Q0 as i32 && curr_reg_id <= arm64::RegisterARM64::Q31 as i32) ||
               (curr_reg_id >= arm64::RegisterARM64::V0 as i32 && curr_reg_id <= arm64::RegisterARM64::V31 as i32) {
                value = vec![0; 16 as usize];
            } else {
                return Err(ucconst::uc_error::ARG)
            }
        } else {
            return Err(ucconst::uc_error::ARCH)
        }
        
        err = unsafe { ffi::uc_reg_read(self.inner.uc, curr_reg_id, value.as_mut_ptr() as _) };

        if err == ucconst::uc_error::OK {
            boxed = value.into_boxed_slice();
            Ok(boxed)
        } else {
            Err(err)
        }
    }

    // Read a signed 32-bit value from a register.
    pub fn reg_read_i32<T: Into<i32>>(&self, regid: T) -> Result<i32, ucconst::uc_error> {
        let mut value: i32 = 0;
        let err = unsafe { ffi::uc_reg_read(self.inner.uc, regid.into(), &mut value as *mut i32 as _) };
        if err == ucconst::uc_error::OK {
            Ok(value)
        } else {
            Err(err)
        }
    }

    pub fn add_code_hook<F: 'static>(
        &mut self,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<ffi::uc_hook, ucconst::uc_error>
    where F: FnMut(UnicornHandle<D>, u64, u32)
    {
        let mut hook_ptr = std::ptr::null_mut();
        let mut user_data = Box::new(ffi::CodeHook {
            unicorn: unsafe { self.inner.as_mut().get_unchecked_mut() } as _,
            callback: Box::new(callback),
        });
        
        let err = unsafe {
            ffi::uc_hook_add(
                self.inner.uc,
                &mut hook_ptr,
                ucconst::HookType::CODE,
                ffi::code_hook_proxy::<D> as _,
                user_data.as_mut() as *mut _ as _,
                begin,
                end,
            )
        };
        if err == ucconst::uc_error::OK {
            unsafe { self.inner.as_mut().get_unchecked_mut() }.code_hooks.insert(hook_ptr, user_data);
            Ok(hook_ptr)
        } else {
            Err(err)
        }
    }

    pub fn add_mem_hook<F: 'static>(
        &mut self,
        hook_type: ucconst::HookType,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<ffi::uc_hook, ucconst::uc_error>
    where F: FnMut(UnicornHandle<D>, ucconst::MemType, u64, usize, i64)
    { 
        let mut hook_ptr = std::ptr::null_mut();
        let mut user_data = Box::new(ffi::MemHook {
            unicorn: unsafe { self.inner.as_mut().get_unchecked_mut() } as _,
            callback: Box::new(callback),
        });
        
        let err = unsafe {
            ffi::uc_hook_add(
                self.inner.uc,
                &mut hook_ptr,
                hook_type,
                ffi::mem_hook_proxy::<D> as _,
                user_data.as_mut() as *mut _ as _,
                begin,
                end,
            )
        };
        if err == ucconst::uc_error::OK {
            unsafe { self.inner.as_mut().get_unchecked_mut() }.mem_hooks.insert(hook_ptr, user_data);
            Ok(hook_ptr)
        } else {
            Err(err)
        }
    }

    pub fn add_intr_hook<F: 'static>(
        &mut self,
        callback: F,
    ) -> Result<ffi::uc_hook, ucconst::uc_error>
    where F: FnMut(UnicornHandle<D>, u32)
    { 
        let mut hook_ptr = std::ptr::null_mut();
        let mut user_data = Box::new(ffi::InterruptHook {
            unicorn: unsafe { self.inner.as_mut().get_unchecked_mut() } as _,
            callback: Box::new(callback),
        });
        
        let err = unsafe {
            ffi::uc_hook_add(
                self.inner.uc,
                &mut hook_ptr,
                ucconst::HookType::INTR,
                ffi::intr_hook_proxy::<D> as _,
                user_data.as_mut() as *mut _ as _,
                0,
                0,
            )
        };
        if err == ucconst::uc_error::OK {
            unsafe { self.inner.as_mut().get_unchecked_mut() }.intr_hooks.insert(hook_ptr, user_data);
            Ok(hook_ptr)
        } else {
            Err(err)
        }
    }

    // only supports x86 subset
    pub fn add_ins_hook<F: 'static>(
        &mut self,
        ins: x86::InsnX86,
        callback: F,
    ) -> Result<ffi::uc_hook, ucconst::uc_error>
    where F: FnMut(UnicornHandle<D>, u32, usize)
    { 
        let mut hook_ptr = std::ptr::null_mut();
        let mut user_data = Box::new(ffi::InstructionHook {
            unicorn: unsafe { self.inner.as_mut().get_unchecked_mut() } as _,
            callback: Box::new(callback),
        });
        
        let err = unsafe {
            ffi::uc_hook_add(
                self.inner.uc,
                &mut hook_ptr,
                ucconst::HookType::INSN,
                ffi::ins_hook_proxy::<D> as _,
                user_data.as_mut() as *mut _ as _,
                0,
                0,
                ins,
            )
        };
        if err == ucconst::uc_error::OK {
            unsafe { self.inner.as_mut().get_unchecked_mut() }.ins_hooks.insert(hook_ptr, user_data);
            Ok(hook_ptr)
        } else {
            Err(err)
        }
    }

    pub fn remove_hook(&mut self, hook: ffi::uc_hook) -> Result<(), ucconst::uc_error> {
        let handle = unsafe { self.inner.as_mut().get_unchecked_mut() };
        let err: ucconst::uc_error;
        if handle.code_hooks.contains_key(&hook) || 
            handle.mem_hooks.contains_key(&hook) ||
            handle.intr_hooks.contains_key(&hook)||
            handle.ins_hooks.contains_key(&hook) {
            err = unsafe { ffi::uc_hook_del(handle.uc, hook) };
            handle.mem_hooks.remove(&hook);
        } else {
            err = ucconst::uc_error::HOOK;
        }

        if err == ucconst::uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    // Allocate and return an empty Unicorn context
    // 
    // To be populated via context_save.
    pub fn context_alloc(&self) -> Result<Context, ucconst::uc_error> {
        let mut empty_context: ffi::uc_context = Default::default();
        let err = unsafe { ffi::uc_context_alloc(self.inner.uc, &mut empty_context) };
        if err == ucconst::uc_error::OK {
            Ok(Context { context: empty_context })
        } else {
            Err(err)
        }
    }

    // Save current Unicorn context to previously allocated Context struct
    pub fn context_save(&self, context: &mut Context) -> Result<(), ucconst::uc_error> {
        let err = unsafe { ffi::uc_context_save(self.inner.uc, context.context) };
        if err == ucconst::uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    // Allocate and return a Context struct initialized with the current CPU context
    // 
    // This can be used for fast rollbacks with context_restore.
    // In case of many non-concurrent context saves, use context_alloc and *_save 
    // individually to avoid unnecessary allocations.
    pub fn context_init(&self) -> Result<Context, ucconst::uc_error> {
        let mut new_context: ffi::uc_context = Default::default();
        let err = unsafe { ffi::uc_context_alloc(self.inner.uc, &mut new_context) };
        if err != ucconst::uc_error::OK {
            return Err(err);
        }
        let err = unsafe { ffi::uc_context_save(self.inner.uc, new_context) };
        if err == ucconst::uc_error::OK {
            Ok(Context { context: new_context })
        } else {
            unsafe { ffi::uc_free(new_context) };
            Err(err)
        }
    }

    // Restore a previously saved Unicorn context
    // 
    // Perform a quick rollback of the CPU context, including registers and some
    // internal metadata. Contexts may not be shared across engine instances with
    // differing arches or modes.
    pub fn context_restore(&self, context: &Context) -> Result<(), ucconst::uc_error> {
        let err = unsafe { ffi::uc_context_restore(self.inner.uc, context.context) };
        if err == ucconst::uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn emu_start(&mut self, begin: u64, until: u64, timeout: u64, count: usize) -> Result<(), ucconst::uc_error> {
        let err = unsafe { ffi::uc_emu_start(self.inner.uc, begin, until, timeout, count as _) };
        if err == ucconst::uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn emu_stop(&mut self) -> Result<(), ucconst::uc_error> {
        let err = unsafe { ffi::uc_emu_stop(self.inner.uc) };
        if err == ucconst::uc_error::OK {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn afl_forkserver_start(&mut self, exits: &[u64]) -> Result<(), ucconst::AflRet> {
        let err = unsafe { ffi::uc_afl_forkserver_start(self.inner.uc, exits.as_ptr(), exits.len()) };
        if err == ucconst::AflRet::ERROR {
            Err(err)
        } else {
            Ok(())
        }
    }

    pub fn afl_fuzz<F: 'static, G: 'static>(&mut self,
            input_file: &str,
            input_placement_callback: F,
            exits: &[u64],
            crash_validation_callback: G,
            always_validate: bool,
            persistent_iters: u32) -> Result<(), ucconst::AflRet> 
        where
            F: FnMut(UnicornHandle<D>, &[u8], i32) -> bool,
            G: FnMut(UnicornHandle<D>, ucconst::uc_error, &[u8], i32) -> bool {
        let afl_fuzz_callback = Box::pin(ffi::AflFuzzCallback {
            unicorn: unsafe { self.inner.as_mut().get_unchecked_mut() }, 
            input_callback: Box::new(input_placement_callback),
            validate_callback: Box::new(crash_validation_callback)
        });
    
        let cstyle_input_file = std::ffi::CString::new(input_file).unwrap();
        let err = unsafe { ffi::uc_afl_fuzz(self.inner.uc,
            cstyle_input_file.as_ptr(),
            ffi::input_placement_callback_proxy::<D> as _,
            exits.as_ptr(), exits.len(),
            ffi::crash_validation_callback_proxy::<D> as _,
            always_validate,
            persistent_iters, 
            &*afl_fuzz_callback as *const _ as _) };
        if err == ucconst::AflRet::ERROR {
            Err(err)
        } else {
            Ok(())
        }
    }
}

