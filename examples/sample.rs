use std::ffi::{c_uchar, c_void};

use unicorn_engine::{ffi::uc_handle, Arch, Mode, Permission, RegisterX86, Unicorn};
use unicornafl::target::child_fuzz;

extern "C" fn place_input_cb(
    uc: uc_handle,
    input: *const c_uchar,
    input_len: usize,
    _persistent_round: u64,
    _data: *mut c_void,
) -> bool {
    let mut uc = unsafe { Unicorn::from_handle(uc) }.expect("fail to create inner");
    let mut buf = [0; 8];
    let input = unsafe { std::slice::from_raw_parts(input, input_len) };
    let cp_len = input.len().min(8);
    buf[0..cp_len].copy_from_slice(input);
    let rdx = u64::from_le_bytes(buf);
    uc.reg_write(RegisterX86::RDX, rdx)
        .expect("Fail to write reg");

    true
}

fn main() {
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64).expect("fail to open uc");
    // ks.asm("mov rax, rdx; cmp rax, 0x114514; je die; xor rax, rax; die: mov rax, [rax]; xor rax, rax")
    let code = b"\x48\x89\xd0\x48\x3d\x14\x45\x11\x00\x74\x03\x48\x31\xc0\x48\x8b\x00\x48\x31\xc0";
    uc.mem_map(0x1000, 0x4000, Permission::all())
        .expect("fail to map");
    uc.mem_write(0x1000, code).expect("fail to write code");
    child_fuzz(
        uc.get_handle(),
        1,
        place_input_cb,
        None,
        vec![0x100b, 0x1011],
        None,
        false,
        true,
        std::ptr::null_mut(),
    )
    .expect("fail to fuzz?")
}
