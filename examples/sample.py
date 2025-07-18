import sys
import unicornafl
from unicorn import *
from unicorn.x86_const import *

def place_input_callback(mu, input_bytes, persistent_round, data):
    # The mode we specified in the command line
    do_x86_64 = data
    if do_x86_64:
        if len(input_bytes) < 8:
            # decline the input
            return False
        buf = bytearray(8)
        cp_len = min(len(input_bytes), 8)
        buf[0:cp_len] = input_bytes[0:cp_len]
        rdx = int.from_bytes(buf, byteorder='little')
        mu.reg_write(UC_X86_REG_RDX, rdx)
    else:
        if len(input_bytes) < 4:
            # decline the input
            return False
        buf = bytearray(4)
        cp_len = min(len(input_bytes), 4)
        buf[0:cp_len] = input_bytes[0:cp_len]
        rdx = int.from_bytes(buf, byteorder='little')
        mu.reg_write(UC_X86_REG_EDX, rdx)

if __name__ == '__main__':
    if len(sys.argv) == 1:
        input_file = None
        do_x86_64 = False
    elif len(sys.argv) == 2:
        input_file = sys.argv[1]
        do_x86_64 = False
    else:
        # If we have a second arguments, solve 8 bytes magic intead, which is more difficult.
        input_file = sys.argv[1]
        do_x86_64 = True

    if do_x86_64:
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        # 8 bytes magic
        # ks.asm("mov rax, rdx; cmp rax, 0x114514; je die; xor rax, rax; die: mov rax, [rax]; xor rax, rax")
        CODE = b"\x48\x89\xd0\x48\x3d\x14\x45\x11\x00\x74\x03\x48\x31\xc0\x48\x8b\x00\x48\x31\xc0"
        exits = [0x100b, 0x1011]
    else:
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        # 4 bytes magic
        # ks.asm("mov eax, edx; cmp eax, 0x114514; je die; xor eax, eax; die: mov eax, [eax]; xor eax, eax")
        CODE = b"\x89\xd0\x3d\x14\x45\x11\x00\x74\x02\x31\xc0\x8b\x00\x31\xc0"
        exits = [
            0x1009, # xor eax, eax after je die
            0x100d  # xor eax, eax in the end
        ]

    mu.mem_map(0x1000, 0x4000)
    mu.mem_write(0x1000, CODE)
    if do_x86_64:
        mu.reg_write(UC_X86_REG_RIP, 0x1000)
    else:
        mu.reg_write(UC_X86_REG_EIP, 0x1000)

    unicornafl.uc_afl_fuzz(
        mu,
        input_file,
        place_input_callback,
        exits,
        data=do_x86_64
    )