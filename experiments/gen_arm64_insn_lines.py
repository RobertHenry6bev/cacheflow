#! /usr/bin/python3
"""
Generate arrmv8 assembly code in runs of length 16
that is eyecatching when it is disassembled.
"""
import argparse

class Generator:
    """An assembly generator."""
    def __init__(self):
        self.byte_addr = 0
    def instruction(self, string):
        """Print out an instruction."""
        print("\t%s" % (string,))
        self.byte_addr += 4
    def data(self, value):
        """Print out a coded instruction which should never execute."""
        print("\t.word 0x%08x" % (value,))
        self.byte_addr += 4
    def label(self, name):
        """Print out a label."""
        print("%s:" % (name,))
        self.byte_addr += 0
    def gen_branch_chain(self, brand_value):
        """Print out a branch forward chain, skipping over icache markers."""
        for _i in range(0, 8):
            self.instruction("b 1f")  # unconditional branch
            self.data(0xffffffff)
            self.data(self.byte_addr)
            self.data((0xeeee << 16) | brand_value)
            self.label("1")

def gen_arm64_instructions():
    """Generate a bunch of interesting unique sequences of
    arm64 instructions to flood the cache.
    """
    parser = argparse.ArgumentParser("write interesting ARMv8 asm code")
    parser.add_argument(
        "--nblocks",
        help="number of blocks to generate",
        type=int,
        default=16,)
    parser.add_argument(
        "--value",
        help="value to embed as a brand in an instruction",
        type=str,
        default="0",)
    args = parser.parse_args()
    gen = Generator()
    value = int(args.value, 0)
    for _block in range(0, args.nblocks):
        gen.gen_branch_chain(value)

if __name__ == "__main__":
    gen_arm64_instructions()
