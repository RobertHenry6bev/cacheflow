#! /usr/bin/python3

"""
Analyze data held in cache looking for long runs of instructions
that span many 16-instruction wide cache lines.
"""

# pylint: disable=too-many-locals

import argparse
import csv

import capstone

IS_L2 = True
if IS_L2:
    FIELD_NAMES = [] \
      + ["check"] \
      + ["way", "set"] \
      + ["moesi"] \
      + ["pid", "pid_x"] \
      + ["rawtag"] \
      + ["phys_addr"] \
      + ["d_%02d" % (i,) for i in range(0, 16)]
    NWAY = 16
    NSET = 1024
else:
    FIELD_NAMES = [] \
      + ["way", "set"] \
      + ["pid", "pid_x"] \
      + ["t1" + "t0"] \
      + ["d_%02d" % (i,) for i in range(0, 16)]
    NWAY =   3
    NSET = 256

class InsnRunAnalyzer:
    """Look for instruction runs of length between lg_lb and lg_ub"""
    def __init__(self, lg_lb, lg_ub):
        self.lg_lb = lg_lb
        self.lg_ub = lg_ub
        self.runcount = {}
    def analyze_insn_run(self, _phys_addr, insns):
        """popcount runs of instructions of various lengths"""
        ninsns = len(insns)
        for run_lg in range(self.lg_lb, self.lg_ub+1):
            for i in range(0, ninsns - run_lg):
                insn_slice = tuple(insns[i:i+run_lg])
                if insn_slice not in self.runcount:
                    self.runcount[insn_slice] = 0
                self.runcount[insn_slice] += 1
    def dump(self, decoder):
        """Dump out the instruction runs."""
        last_len = 0
        # by descending count
        # for insn_slice, count in sorted(self.runcount.items(), reverse=True, key=lambda x:x[1]):
        # by descending length of run
        for insn_slice, count in sorted(self.runcount.items(),
                reverse=True, key=lambda x: len(x[0])):
            if last_len != len(insn_slice):
                last_len = len(insn_slice)
                print("")
            if count <= 1:
                continue
            decode = ""
            sep = ""
            for content in insn_slice:
                decoded_value = decoder.decode(0x0, content)
                if decoded_value:
                    if len(decoded_value) == 2:
                        decode += "%s%s %s" % (sep, decoded_value[0], decoded_value[1],)
                    else:
                        decode += "%s%s" % (sep, decoded_value[0],)
                    sep = "; "
            print("%8d lg=%d %s" % (count, len(insn_slice), decode))

class InstructionDecoder:
    """Given a 4-byte uint32_t ARM64 instruction,
    decode it into a mnemonic and op_str, if possible.
    Cache the results, as Capstone takes a long time.
    """
    def __init__(self):
        self.capstone_engine = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        self.insn_value_to_decode = {}
    def dump(self):
        """Print out the cache."""
        # print(self.insn_value_to_decode)
        print("%d instructions in the decode cache" % (len(self.insn_value_to_decode),))
    def decode(self, phys_addr, insn_value):
        """Returns None if insn_value isn't decodable.
        Otherwise returns a list of length 1 or 2,
        the first item is the mnemonic(opcode), 2nd the op_str.
        """
        if insn_value in self.insn_value_to_decode:
            return self.insn_value_to_decode[insn_value]
        ndecoded = 0
        decode_value = None
        for insn in self.capstone_engine.disasm(insn_value.to_bytes(4, "little"), phys_addr):
            decode_value = [insn.mnemonic, insn.op_str]
            ndecoded += 1
        assert 0 <= ndecoded <= 1
        if ndecoded == 0:
            self.insn_value_to_decode[insn_value] = None
            return None
        self.insn_value_to_decode[insn_value] = decode_value
        return decode_value
    def is_instruction(self, phys_addr, insn_value):
        """Return True if this decodes as a valid instruction."""
        return self.decode(phys_addr, insn_value) is not None

def consume_csv_file_analyze(input_fd):
    """Read a csv file, doing analysis."""
    do_print = False
    # run_analyzer = InsnRunAnalyzer(5, 16)
    run_analyzer = InsnRunAnalyzer(5, 6)
    decoder = InstructionDecoder()

    reader = csv.DictReader(input_fd, fieldnames=FIELD_NAMES)
    #
    # Read all rows, and store internally,
    # so we can display the image with NWAYS ways going left to right.
    #
    contents = {}  # indexed by phys_addr
    addr_to_pid = {}
    for row in reader:
        phys_addr = int(row["phys_addr"], 16)
        pid = int(row["pid"])
        insns = [int(row["d_%02d" % (i,)], 16) for i in range(0, 16)]
        contents[phys_addr] = insns
        addr_to_pid[phys_addr] = pid

    new_contents = {}
    new_addr_to_pid = {}
    last_phys_addr = -1
    for phys_addr in sorted(contents.keys()):
        if (last_phys_addr in contents) and \
                (phys_addr == (last_phys_addr + 4 * len(new_contents[last_phys_addr]))):
            new_contents[last_phys_addr] = new_contents[last_phys_addr] + contents[phys_addr]
            assert new_addr_to_pid[last_phys_addr] == addr_to_pid[phys_addr]
        else:
            last_phys_addr = phys_addr
            new_contents[last_phys_addr] = contents[phys_addr]
            new_addr_to_pid[last_phys_addr] = addr_to_pid[phys_addr]
    for phys_addr in sorted(new_contents.keys()):
        if do_print:
            print("0x%016x: %4d" % (phys_addr, len(new_contents[phys_addr]),))
        total_decoded = 0
        byte_delta = 0
        for content in new_contents[phys_addr]:
            if decoder.is_instruction(phys_addr + byte_delta, content):
                total_decoded += 1
            byte_delta += 4
        if total_decoded == len(new_contents[phys_addr]):
            run_analyzer.analyze_insn_run(phys_addr, new_contents[phys_addr])
    run_analyzer.dump(decoder)
    decoder.dump()

def analyze_cache_contents():
    """Analyze cache contents."""
    parser = argparse.ArgumentParser("analyze cache contents")
    parser.add_argument(
        "rest",
        nargs=argparse.REMAINDER,)
    args = parser.parse_args()
    for input_file_name in args.rest:
        print("Reading %s" % (input_file_name,))
        with open(input_file_name, "r") as input_fd:
            consume_csv_file_analyze(input_fd)

if __name__ == "__main__":
    analyze_cache_contents()
