#![allow(non_snake_case)]
extern crate libc;

use crate::{
    ffi::uc_hook,
    unicorn_const::{uc_error, Arch, HookType, MemType, Mode, Permission},
    RegisterARM,
};
use capstone::prelude::*;
use libc::{c_void, mmap, munmap, size_t, MAP_ANON, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use std::{cell::RefCell, collections::HashMap, ptr};

#[derive(Debug)]
pub struct Chunk {
    pub offset: u64,
    pub len: size_t,
    pub freed: bool,
}

#[derive(Debug)]
pub struct Heap {
    pub real_base: *mut c_void,
    pub uc_base: u64,
    pub size: size_t,
    pub grow_dynamically: bool,
    pub chunk_map: HashMap<u64, Chunk>,
    pub top: u64,
    /// offset of the unalloc hook in this
    pub unalloc_hook_idx: usize,
    pub own_hooks: Vec<uc_hook>,
}

impl Heap {
    fn unalloc_hook(&self) -> uc_hook {
        self.own_hooks[self.unalloc_hook_idx]
    }

    fn unalloc_hook_replace(&mut self, new_unalloc_hook: uc_hook) {
        let unalloc_hook_idx = self.unalloc_hook_idx;
        self.own_hooks[unalloc_hook_idx] = new_unalloc_hook;
    }
}

impl Drop for Heap {
    fn drop(&mut self) {
        unsafe {
            munmap(self.real_base as *mut c_void, self.size);
        }
    }
}

/// Hooks (parts of the) code segment to display register info and the current instruction.
pub fn add_debug_prints_ARM<D>(uc: &mut super::Unicorn<'_, D>, code_start: u64, code_end: u64) {
    let cs_arm: Capstone = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Arm)
        .detail(true)
        .build()
        .expect("failed to create capstone for ARM");

    let cs_thumb: Capstone = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Thumb)
        .detail(true)
        .build()
        .expect("failed to create capstone for thumb");

    let callback = Box::new(move |uc: &mut super::Unicorn<D>, addr: u64, size: u32| {
        let sp = uc
            .reg_read(RegisterARM::SP as i32)
            .expect("failed to read SP");
        let lr = uc
            .reg_read(RegisterARM::LR as i32)
            .expect("failed to read LR");
        let r0 = uc
            .reg_read(RegisterARM::R0 as i32)
            .expect("failed to read r0");
        let r1 = uc
            .reg_read(RegisterARM::R1 as i32)
            .expect("failed to read r1");
        let r2 = uc
            .reg_read(RegisterARM::R2 as i32)
            .expect("failed to read r2");
        let r3 = uc
            .reg_read(RegisterARM::R3 as i32)
            .expect("failed to read r3");
        let r4 = uc
            .reg_read(RegisterARM::R4 as i32)
            .expect("failed to read r4");
        let r5 = uc
            .reg_read(RegisterARM::R5 as i32)
            .expect("failed to read r5");
        let r6 = uc
            .reg_read(RegisterARM::R6 as i32)
            .expect("failed to read r6");
        let r7 = uc
            .reg_read(RegisterARM::R7 as i32)
            .expect("failed to read r7");
        let r8 = uc
            .reg_read(RegisterARM::R8 as i32)
            .expect("failed to read r8");
        let r9 = uc
            .reg_read(RegisterARM::R9 as i32)
            .expect("failed to read r9");
        let r10 = uc
            .reg_read(RegisterARM::R10 as i32)
            .expect("failed to read r10");
        let r11 = uc
            .reg_read(RegisterARM::R11 as i32)
            .expect("failed to read r11");
        println!("________________________________________________________________________\n");
        println!(
            "$r0: {:#010x}   $r1: {:#010x}    $r2: {:#010x}    $r3: {:#010x}",
            r0, r1, r2, r3
        );
        println!(
            "$r4: {:#010x}   $r5: {:#010x}    $r6: {:#010x}    $r7: {:#010x}",
            r4, r5, r6, r7
        );
        println!(
            "$r8: {:#010x}   $r9: {:#010x}   $r10: {:#010x}   $r11: {:#010x}",
            r8, r9, r10, r11
        );
        println!("$sp: {:#010x}   $lr: {:#010x}\n", sp, lr);

        // decide which mode (ARM/Thumb) to use for disasm
        let cpsr = uc
            .reg_read(RegisterARM::CPSR as i32)
            .expect("failed to read CPSR");
        let mut buf = vec![0; size as usize];
        uc.mem_read(addr, &mut buf)
            .expect("failed to read opcode from memory");
        let ins = if cpsr & 0x20 == 0 {
            cs_arm.disasm_all(&buf, u64::from(size))
        } else {
            cs_thumb.disasm_all(&buf, u64::from(size))
        }
        .unwrap_or_else(|_| panic!("failed to disasm at addr {:#010x}", addr));
        println!("$pc: {:#010x}", addr);
        println!("{}", ins);
    });

    uc.add_code_hook(code_start, code_end, callback)
        .expect("failed to set debug hook");
}

/// Returns a new Unicorn instance with an initialized heap and active sanitizer.
///
/// Introduces an accessible way of dynamic memory allocation for emulation and helps
/// detecting common memory corruption bugs.
/// The allocator makes heavy use of Unicorn hooks for sanitization/ crash amplification
/// and thus introduces some overhead.
pub fn init_emu_with_heap<'a>(
    arch: Arch,
    mode: Mode,
    mut size: u32,
    base_addr: u64,
    grow: bool,
) -> Result<super::Unicorn<'a, RefCell<Heap>>, uc_error> {
    let heap = RefCell::new(Heap {
        real_base: 0 as _,
        uc_base: 0,
        size: 0,
        grow_dynamically: false,
        chunk_map: HashMap::new(),
        top: 0,
        unalloc_hook_idx: 0_usize,
        own_hooks: Vec::with_capacity(16),
    });

    let mut uc = super::Unicorn::new_with_data(arch, mode, heap)?;

    // uc memory regions have to be 8 byte aligned
    if size % 8 != 0 {
        size = ((size / 8) + 1) * 8;
    }

    // init heap management struct for later use within unicorn
    let null_ptr = ptr::null_mut();
    unsafe {
        // manually mmap space for heap to know location
        let arena_ptr = mmap(
            null_ptr,
            size as usize,
            PROT_READ | PROT_WRITE,
            MAP_ANON | MAP_PRIVATE,
            0,
            0,
        );
        if arena_ptr.is_null() {
            return Err(uc_error::ARG);
        }
        uc.mem_map_ptr(
            base_addr,
            size as usize,
            Permission::READ | Permission::WRITE,
            arena_ptr,
        )?;

        // set the initial unalloc hook
        let unalloc_hook = uc.add_mem_hook(
            HookType::MEM_VALID,
            base_addr,
            base_addr + u64::from(size),
            heap_unalloc,
        )?;

        let chunks = HashMap::new();
        let heap: &mut Heap = &mut *uc.get_data().borrow_mut();
        heap.real_base = arena_ptr; // heap pointer in process mem
        heap.uc_base = base_addr;
        heap.size = size as usize;
        /*
        let the heap grow dynamically
        (ATTENTION: There are no guarantees that the heap segment will be continuous in process mem any more)
        */
        heap.grow_dynamically = grow;
        heap.chunk_map = chunks;
        heap.top = base_addr; // pointer to top of heap in unicorn mem, increases on allocations

        heap.own_hooks.push(unalloc_hook);
        heap.unalloc_hook_idx = heap.own_hooks.len() - 1; // hook ID, needed to rearrange hooks on allocations
    }

    Ok(uc)
}

/// `malloc` for the utils allocator.
///
/// Returns a pointer into memory used as heap and applies
/// canary hooks to detect out-of-bounds accesses.
/// Grows the heap if necessary and if it is configured to, otherwise
/// return `WRITE_UNMAPPED` if there is no space left.
pub fn uc_alloc(uc: &mut super::Unicorn<RefCell<Heap>>, mut size: u64) -> Result<u64, uc_error> {
    // 8 byte aligned
    if size % 8 != 0 {
        size = ((size / 8) + 1) * 8;
    }
    let mut heap_info = uc.get_data().borrow_mut();
    let addr = heap_info.top;
    let mut len = heap_info.size;
    let uc_base = heap_info.uc_base;

    if addr + size >= uc_base + len as u64 {
        if heap_info.grow_dynamically {
            // grow heap
            let mut increase_by = len / 2;
            if increase_by % 8 != 0 {
                increase_by = ((increase_by / 8) + 1) * 8;
            }
            heap_info.size += increase_by;
            let new_len = heap_info.size;
            drop(heap_info);
            uc.mem_map(
                uc_base + len as u64,
                increase_by,
                Permission::READ | Permission::WRITE,
            )?;
            len = new_len;
        } else {
            return Err(uc_error::WRITE_UNMAPPED);
        }
    } else {
        drop(heap_info);
    }

    // canary hooks
    let mut new_hooks = vec![
        uc.add_mem_hook(HookType::MEM_WRITE, addr, addr + 3, heap_bo)?,
        uc.add_mem_hook(HookType::MEM_READ, addr, addr + 3, heap_oob)?,
        uc.add_mem_hook(
            HookType::MEM_WRITE,
            addr + 4 + size,
            addr + 4 + size + 3,
            heap_bo,
        )?,
        uc.add_mem_hook(
            HookType::MEM_READ,
            addr + 4 + size,
            addr + 4 + size + 3,
            heap_oob,
        )?,
    ];
    {
        let hooks = &mut uc.get_data().borrow_mut().own_hooks;
        hooks.append(&mut new_hooks);
    }

    // add new chunk
    let curr_offset = addr + 4 - uc_base;
    let curr_chunk = Chunk {
        offset: curr_offset,
        len: size as size_t,
        freed: false,
    };
    uc.get_data()
        .borrow_mut()
        .chunk_map
        .insert(addr + 4, curr_chunk);
    let new_top = uc.get_data().borrow_mut().top + size + 8; // canary*2
    #[cfg(debug_assertions)]
    println!(
        "[+] New Allocation from {:#010x} to {:#010x} (size: {})",
        uc.get_data().borrow().top,
        uc.get_data().borrow().top + size - 1 + 8,
        size
    );
    uc.get_data().borrow_mut().top = new_top;

    // replace unalloc hook
    let old_hook = uc.get_data().borrow_mut().unalloc_hook();
    uc.remove_hook(old_hook)?;

    let new_hook = {
        uc.add_mem_hook(
            HookType::MEM_VALID,
            new_top,
            uc_base + len as u64,
            heap_unalloc,
        )?
    };

    uc.get_data().borrow_mut().unalloc_hook_replace(new_hook);
    uc.get_data().borrow_mut().own_hooks.push(new_hook);

    Ok(addr + 4)
}

/// `free` for the utils allocator.
///
/// Marks the chunk to be freed to detect double-frees later on
/// and places sanitization hooks over the freed region to detect
/// use-after-frees.
pub fn uc_free(uc: &mut super::Unicorn<RefCell<Heap>>, ptr: u64) -> Result<(), uc_error> {
    #[cfg(debug_assertions)]
    println!("[-] Freeing {:#010x}", ptr);

    if ptr != 0x0 {
        #[allow(unused_assignments)]
        let mut chunk_size = 0;
        {
            let mut heap = uc.get_data().borrow_mut();
            let curr_chunk = heap
                .chunk_map
                .get_mut(&ptr)
                .expect("failed to find requested chunk on heap");
            chunk_size = curr_chunk.len as u64;
            assert!(
                !curr_chunk.freed,
                "ERROR: unicorn-rs Sanitizer: Double Free detected on addr {:#0x}, $pc: {:#010x}",
                ptr,
                uc.pc_read().unwrap()
            );
            curr_chunk.freed = true;
        }

        let new_hook = uc.add_mem_hook(HookType::MEM_VALID, ptr, ptr + chunk_size - 1, heap_uaf)?;
        {
            let mut heap = uc.get_data().borrow_mut();
            heap.own_hooks.push(new_hook);
        }
    }
    Ok(())
}

/// Reset the drop-in heap to an empty state
pub fn uc_heap_reset(uc: &mut super::Unicorn<RefCell<Heap>>) -> Result<(), uc_error> {
    let (hooks, base_addr, size) = {
        let mut heap = uc.get_data().borrow_mut();
        let hooks: Vec<uc_hook> = heap.own_hooks.drain(..).collect();
        let base_addr = heap.uc_base;
        let size = heap.size;
        (hooks, base_addr, size)
    };

    for hook in hooks {
        uc.remove_hook(hook)?;
    }

    // set the initial unalloc hook
    let unalloc_hook = uc.add_mem_hook(
        HookType::MEM_VALID,
        base_addr,
        base_addr + size as u64,
        heap_unalloc,
    )?;

    let mut heap = uc.get_data().borrow_mut();
    heap.own_hooks.push(unalloc_hook);
    heap.unalloc_hook_idx = heap.own_hooks.len() - 1; // hook ID, needed to rearrange hooks on allocations

    Ok(())
}

/// Error callback on heap oob access for unallocated memory
fn heap_unalloc(
    uc: &mut super::Unicorn<RefCell<Heap>>,
    _mem_type: MemType,
    addr: u64,
    _size: usize,
    _val: i64,
) -> bool {
    let pc = uc.pc_read().expect("failed to read pc");
    panic!("ERROR: unicorn-rs Sanitizer: Heap out-of-bounds access of unallocated memory on addr {:#0x}, $pc: {:#010x}",
        addr, pc);
}

/// Error callback on heap oob read
fn heap_oob(
    uc: &mut super::Unicorn<RefCell<Heap>>,
    _mem_type: MemType,
    addr: u64,
    _size: usize,
    _val: i64,
) -> bool {
    let pc = uc.pc_read().unwrap();
    panic!(
        "ERROR: unicorn-rs Sanitizer: Heap out-of-bounds read on addr {:#0x}, $pc: {:#010x}",
        addr, pc
    );
}

/// Error callback on heap oob write
fn heap_bo(
    uc: &mut super::Unicorn<RefCell<Heap>>,
    _mem_type: MemType,
    addr: u64,
    _size: usize,
    _val: i64,
) -> bool {
    let pc = uc.pc_read().unwrap();
    panic!(
        "ERROR: unicorn-rs Sanitizer: Heap buffer-overflow on addr {:#0x}, $pc: {:#010x}",
        addr, pc
    );
}

/// Error callback for `use-after-free`
fn heap_uaf(
    uc: &mut super::Unicorn<RefCell<Heap>>,
    _mem_type: MemType,
    addr: u64,
    _size: usize,
    _val: i64,
) -> bool {
    panic!(
        "ERROR: unicorn-rs Sanitizer: Heap use-after-free on addr {:#0x}, $pc: {:#010x}",
        addr,
        uc.pc_read().unwrap()
    );
}

/// print Unicorn's memory regions
pub fn vmmap<D>(uc: &mut super::Unicorn<D>) {
    let regions = uc
        .mem_regions()
        .expect("failed to retrieve memory mappings");
    println!("Regions : {}", regions.len());

    for region in &regions {
        println!("{:#010x?}", region);
    }
}
