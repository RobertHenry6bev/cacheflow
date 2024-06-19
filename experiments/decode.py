#! /usr/bin/python3
"""
Read from stdin an uint32, and print its ARM64 instruction.
"""
import sys

import capstone
capstone_engine = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

def decode_insn(insn_value):
    """Decode and print the instruction."""
    count = 0
    for insn in capstone_engine.disasm(insn_value.to_bytes(4, "little"), 0x0):
        count += 1
        print("0x%08x %s %s" % (insn_value, insn.mnemonic, insn.op_str,))
    if count == 0:
        print("??")

def read_stdin_print_ints():
    """Read one integer per line from stdin, and print the decode."""
    for line in sys.stdin:
        insn_value = int(line, 0) & 0xffffffff
        decode_insn(insn_value)

if __name__ == "__main__":
    read_stdin_print_ints()
