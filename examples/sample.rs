use std::path::PathBuf;

use unicorn_engine::{Arch, Mode, Prot, RegisterX86, Unicorn};
use unicornafl::{afl_fuzz, executor::UnicornFuzzData};

fn place_input_cb<'a, D: 'a>(
    uc: &mut Unicorn<'a, UnicornFuzzData<D>>,
    input: &[u8],
    _persistent_round: u64,
) -> bool {
    let mut buf = [0; 8];
    if input.len() < 8 {
        // decline the input
        return false;
    }
    let cp_len = input.len().min(8);
    buf[0..cp_len].copy_from_slice(&input[0..cp_len]);
    let rdx = u64::from_le_bytes(buf);
    uc.reg_write(RegisterX86::RDX, rdx)
        .expect("Fail to write reg");

    true
}

fn main() {
    let input_file = std::env::args().nth(1);
    let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, UnicornFuzzData::default())
        .expect("fail to open uc");
    // ks.asm("mov rax, rdx; cmp rax, 0x114514; je die; xor rax, rax; die: mov rax, [rax]; xor rax, rax")
    let code = b"\x48\x89\xd0\x48\x3d\x14\x45\x11\x00\x74\x03\x48\x31\xc0\x48\x8b\x00\x48\x31\xc0";
    uc.mem_map(0x1000, 0x4000, Prot::ALL).expect("fail to map");
    uc.mem_write(0x1000, code).expect("fail to write code");
    let pc = 0x1000;
    uc.reg_write(RegisterX86::RIP, pc)
        .expect("fail to write pc");
    let input_file = input_file.map(PathBuf::from);
    afl_fuzz(
        uc,
        input_file,
        place_input_cb,
        vec![0x100b, 0x1011],
        false,
        1,
    )
    .expect("fail to fuzz?")
}
