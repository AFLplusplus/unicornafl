extern crate libc;

use capstone::prelude::*;
use super::arm::Register;
use super::ffi::{Protection, Mode, Arch, HookType};
use std::ptr;
use std::cell::RefCell;
use std::collections::HashMap;
use libc::{mmap, munmap, c_void, size_t, MAP_ANON, MAP_PRIVATE,PROT_READ,PROT_WRITE};



#[derive(Debug)]
pub struct Chunk {
    pub offset: u64,
    pub len: size_t,
}

#[derive(Debug)]
pub struct Heap {
    pub real_base: *mut c_void,
    pub uc_base: u64,
    pub len: size_t,
    pub chunk_map: HashMap<u64, Chunk>,
    pub top: u64,
    pub oob_hook: super::ffi::uc_hook, //TODO make private
}

fn vmmap<D>(uc: &mut super::UnicornHandle<D>) {
    let regions = uc
        .mem_regions()
        .expect("failed to retrieve memory mappings");
    println!("Regions : {}", regions.len());

    for region in &regions {
        println!("{:#010x?}", region);
    }
}


fn heap_oob(mut uc: super::UnicornHandle<RefCell<Heap>>, mem_type: super::ffi::MemType, addr: u64, size: usize, val: i64) { 
    #[cfg(debug_assertions)]
    println!("");      
    panic!("ERROR: unicornafl Sanitizer: heap-out-of-bounds access on address {:#020x}", addr);
}


// hooks (parts of the) code segment with a reginfo and current instruction overview
pub fn add_debug_prints_ARM<D>(uc: &mut super::UnicornHandle<D>, code_start: u64, code_end: u64) {
    let cs_arm: Capstone = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Arm)
        .detail(true)
        .build().expect("failed to create capstone for ARM");

    let cs_thumb: Capstone = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Thumb)
        .detail(true)
        .build().expect("failed to create capstone for thumb");

    let callback = Box::new(move |uc: super::UnicornHandle<D>, addr: u64, size: u32| {        
        let sp = uc.reg_read(Register::SP as i32).expect("failed to read SP");
        let lr = uc.reg_read(Register::LR as i32).expect("failed to read LR");
        let r0 = uc.reg_read(Register::R0 as i32).expect("failed to read r0");
        let r1 = uc.reg_read(Register::R1 as i32).expect("failed to read r1");
        let r2 = uc.reg_read(Register::R2 as i32).expect("failed to read r2");
        let r3 = uc.reg_read(Register::R3 as i32).expect("failed to read r3");
        let r4 = uc.reg_read(Register::R4 as i32).expect("failed to read r4");
        let r5 = uc.reg_read(Register::R5 as i32).expect("failed to read r5");
        let r6 = uc.reg_read(Register::R6 as i32).expect("failed to read r6");
        let r7 = uc.reg_read(Register::R7 as i32).expect("failed to read r7");
        let r8 = uc.reg_read(Register::R8 as i32).expect("failed to read r8");
        let r9 = uc.reg_read(Register::R9 as i32).expect("failed to read r9");
        let r10 = uc.reg_read(Register::R10 as i32).expect("failed to read r10");
        let r11 = uc.reg_read(Register::R11 as i32).expect("failed to read r11");
        println!("________________________________________________________________________\n");
        println!("$r0: {:#010x}   $r1: {:#010x}    $r2: {:#010x}    $r3: {:#010x}", r0, r1, r2, r3);
        println!("$r4: {:#010x}   $r5: {:#010x}    $r6: {:#010x}    $r7: {:#010x}", r4, r5, r6, r7);
        println!("$r8: {:#010x}   $r9: {:#010x}   $r10: {:#010x}   $r11: {:#010x}", r8, r9, r10, r11);
        println!("$sp: {:#010x}   $lr: {:#010x}\n", sp, lr);
        
        // decide which mode (ARM/Thumb) to use for disasm
        let cpsr = uc.reg_read(Register::CPSR as i32).expect("failed to read CPSR");
        let mut buf = vec![0; size as usize];
        uc.mem_read(addr, &mut buf).expect("failed to read opcode from memory");
        let ins = if cpsr & 0x20 != 0 {
            cs_thumb.disasm_all(&buf, size as u64)
        } else {
            cs_arm.disasm_all(&buf, size as u64)
        }.expect(&format!("failed to disasm at addr {:#010x}", addr));
        println!("$pc: {:#010x}", addr);
        println!("{}", ins);
    });

    uc.add_code_hook(HookType::CODE, code_start, code_end, callback).expect("failed to set debug hook");
}


// returns a new unicorn object with an initialized heap @addr 
pub fn init_emu_with_heap(size: u32, base_addr: u64) -> Result<super::Unicorn<RefCell<Heap>>, super::ffi::uc_error> {
    let heap = RefCell::new(Heap {real_base: 0 as _, uc_base: 0, len: 0, chunk_map: HashMap::new(), top: 0, oob_hook: 0 as _ });
    let mut unicorn = super::Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN, heap)?;
    let mut uc = unicorn.borrow(); // get handle

    // init heap management struct for later use within unicorn
    let null_ptr = ptr::null_mut();
    unsafe {
        // manually mmap space for heap to know location
        let arena_ptr = mmap(null_ptr, size as usize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
        uc.mem_map_ptr(base_addr, size as usize, Protection::READ | Protection::WRITE, arena_ptr).expect("failed to map heap arena into unicorn");
        let h = uc.add_mem_hook(HookType::MEM_READ, base_addr, 0x91400000, Box::new(heap_oob)).expect("failed to add heap MEM_READ hook");
        let chunks = HashMap::new();
        let heap: &mut Heap = &mut *uc.get_data().borrow_mut();
        heap.real_base = arena_ptr; // heap pointer in process mem
        heap.uc_base = base_addr;
        heap.len = size as usize;
        heap.chunk_map = chunks;
        heap.top = base_addr; // heap pointer in unicorn mem, increases as heap grows
        heap.oob_hook = h; // hook ID, needed to rearrange hooks when heap grows
    }

    return Ok(unicorn);
}
