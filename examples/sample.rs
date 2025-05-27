use std::path::PathBuf;

use unicorn_engine::{Arch, Mode, Prot, RegisterX86, Unicorn};
use unicornafl::{afl_fuzz, executor::UnicornFuzzData};

fn place_input_cb<'a>(
    uc: &mut Unicorn<'a, UnicornFuzzData<bool>>,
    input: &[u8],
    _persistent_round: u64,
) -> bool {
    // The mode we specified in the command line
    let do_x86_64 = uc.get_data().user_data;
    if do_x86_64 {
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
    } else {
        let mut buf = [0; 4];
        if input.len() < 4 {
            // decline the input
            return false;
        }
        let cp_len = input.len().min(4);
        buf[0..cp_len].copy_from_slice(&input[0..cp_len]);
        let edx = u32::from_le_bytes(buf);
        uc.reg_write(RegisterX86::EDX, edx as _)
            .expect("Fail to write reg");
    }

    true
}

fn main() {
    let input_file = std::env::args().nth(1);
    // If we have a second arguments, solve 8 bytes magic intead, which is more difficult.
    let do_x86_64 = std::env::args().nth(2).is_some();

    let mut uc = if do_x86_64 {
        Unicorn::new_with_data(Arch::X86, Mode::MODE_64, UnicornFuzzData::new(do_x86_64))
            .expect("fail to open uc")
    } else {
        Unicorn::new_with_data(Arch::X86, Mode::MODE_32, UnicornFuzzData::new(do_x86_64))
            .expect("fail to open uc")
    };

    let code = if do_x86_64 {
        // 8 bytes magic
        // ks.asm("mov rax, rdx; cmp rax, 0x114514; je die; xor rax, rax; die: mov rax, [rax]; xor rax, rax")
        b"\x48\x89\xd0\x48\x3d\x14\x45\x11\x00\x74\x03\x48\x31\xc0\x48\x8b\x00\x48\x31\xc0".to_vec()
    } else {
        // 4 bytes magic
        // ks.asm("mov eax, edx; cmp eax, 0x114514; je die; xor eax, eax; die: mov eax, [eax]; xor eax, eax")
        b"\x89\xd0\x3d\x14\x45\x11\x00\x74\x02\x31\xc0\x8b\x00\x31\xc0".to_vec()
    };

    uc.mem_map(0x1000, 0x4000, Prot::ALL).expect("fail to map");
    uc.mem_write(0x1000, &code).expect("fail to write code");
    let pc = 0x1000;
    uc.set_pc(pc).expect("fail to write pc");

    let exits = if do_x86_64 {
        vec![0x100b, 0x1011]
    } else {
        vec![
            0x1009, // xor eax, eax after je die
            0x100d, // xor eax, eax in the end
        ]
    };

    let input_file = input_file.map(PathBuf::from);
    afl_fuzz(uc, input_file, place_input_cb, exits, false, Some(1)).expect("fail to fuzz?")
}
