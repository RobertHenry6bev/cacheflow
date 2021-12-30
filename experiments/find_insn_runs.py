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

class RunCountAccumulator:
    """This is an accumulator when counting run frequency."""
    def __init__(self):
        self.count = 0
        self.pids = []
        self.addrs = []

    def incr(self, _key, pid, addr):
        """Increment ourselves"""
        self.count += 1
        self.pids.append(pid)
        self.addrs.append(addr)

    def decr(self, key, pid, addr):
        """Decrement ourselves"""
        print("decr key=%s pid=%d addr=0x%016x count=%d len=%d" % (key, pid, addr, self.count, len(self.pids),))
        assert len(self.pids) == len(self.addrs)
        assert len(self.pids) == self.count
        if self.count > 0:
            for i in range(0, len(self.pids)):
                if (self.pids[i] == pid) and (self.addrs[i] == addr):
                    self.count -= 1
                    self.pids.pop(i)
                    self.addrs.pop(i)
                    return
            print("decr did not find pid %d and addr 0x%016x" % (pid, addr,))  # TODO: make assert

class InsnRunAnalyzer:
    """Look for instruction runs of length between lg_lb and lg_ub.
    This is done by brute force using a single large map of tuples
    of varying length.  There is no pruning."""
    def __init__(self, lg_lb, lg_ub):
        self.lg_lb = lg_lb
        self.lg_ub = lg_ub
        self.runcount = {}

    def print_insn_run(self, pid, phys_addr, insns, decoder):
        """Print an instruction run."""
        for i in range(0, len(insns)):
            insn = insns[i]
            insn_phys_addr = phys_addr + i*4
            print("%6d %3d 0x%016x 0x%08x %s" % (
                pid,
                i,
                insn_phys_addr,
                insn,
                decoder.decode_to_str(insn_phys_addr, insn),
                ))
        print("")

    def analyze_insn_run(self, pid, phys_addr, insns, decoder):
        """popcount runs of instructions of various lengths"""
        if False:
            self.print_insn_run(pid, phys_addr, insns, decoder)
        self._process_insn_run(pid, phys_addr, insns, decoder, self.lg_lb, self.lg_ub, True)

    def _process_insn_run(self, pid, phys_addr, insns, decoder, xlg_lb, xlg_ub, incr):
        """Private helper function to create all O(N**2) sublists length < N."""
        ninsns = len(insns)
        for run_lg in range(xlg_lb, xlg_ub+1):
            for i in range(0, ninsns - run_lg):
                insn_slice = tuple(insns[i:i+run_lg])
                if incr:
                    if insn_slice not in self.runcount:
                        self.runcount[insn_slice] = RunCountAccumulator()
                    self.runcount[insn_slice].incr(insn_slice, pid, phys_addr + i * 4)
                else:
                    self.runcount[insn_slice].decr(insn_slice, pid, phys_addr + i * 4)

    def prune(self, decoder):
        """Prune away small matches implied by larger matches."""
        nslices = 0
        for insn_slice, accum_object in sorted(self.runcount.items(),
                reverse=True, key=lambda x: 100*len(x[0])+x[1].count):
            nslices += 1
            if accum_object.count <= 0:
                continue
            insns = list(insn_slice)
            print("start prune with %s" % (insns,))
            for i in range(0, len(accum_object.pids)):
                print("count=%d i=%d pid=%d addr=0x%016x" % (
                    accum_object.count,
                    i,
                    accum_object.pids[i],
                    accum_object.addrs[i],))
                self._process_insn_run(
                    accum_object.pids[i],
                    accum_object.addrs[i],
                    insns,
                    decoder,
                    self.lg_lb, len(insn_slice)-1,
                    False)
            if nslices > 10:
                print("stop prune after examine %d slices." % (nslices,))
                break

    def dump(self, decoder):
        """Dump out the instruction runs."""
        last_len = 0
        # sort by descending length of run
        for insn_slice, accum_object in sorted(self.runcount.items(),
                reverse=True, key=lambda x: 100*len(x[0])+x[1].count):
            if last_len != len(insn_slice):
                last_len = len(insn_slice)
                print("")
            if accum_object.count <= 1:
                continue
            decode = ""
            sep = ""
            for insn in insn_slice:
                decoded_value = decoder.decode(0x0, insn)
                if decoded_value:
                    if len(decoded_value) == 2:
                        decode += "%s%s %s" % (sep, decoded_value[0], decoded_value[1],)
                    else:
                        decode += "%s%s" % (sep, decoded_value[0],)
                    sep = "; "
            print("%8d lg=%d pids=%s addrs=%s insns=%s %s" % (
                 accum_object.count,
                 len(insn_slice),
                 accum_object.pids,
                 ["0x%016x" % (addr,) for addr in accum_object.addrs],
                 ["0x%08x" % (insn,) for insn in insn_slice],
                 decode,
                 ))

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

    def decode_to_str(self, phys_addr, insn_value):
        """decode the instruction to a printable string."""
        decoded = self.decode(phys_addr, insn_value)
        if decoded is None:
            return "??"
        if len(decoded) == 1:
            return decoded[0]
        else:
            return "%s %s" % (decoded[0], decoded[1],)

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

def consume_csv_file_analyze(input_fd, lg_lb, lg_ub):
    """Read a csv file, doing analysis."""
    do_print = False
    do_skip_pid0 = True
    run_analyzer = InsnRunAnalyzer(lg_lb, lg_ub)
    decoder = InstructionDecoder()

    reader = csv.DictReader(input_fd, fieldnames=FIELD_NAMES)
    #
    # Read all rows, and store internally,
    # so we can display the image with NWAYS ways going left to right.
    #
    addr_to_insns = {}  # indexed by phys_addr
    addr_to_pid = {}
    for row in reader:
        phys_addr = int(row["phys_addr"], 16)
        pid = int(row["pid"])
        insns = [int(row["d_%02d" % (i,)], 16) for i in range(0, 16)]
        if do_skip_pid0 and pid == 0:
            continue
        addr_to_insns[phys_addr] = insns
        addr_to_pid[phys_addr] = pid

    #
    # Concatenate lines together if their phys addrs are adjacent.
    #
    new_contents = {}
    new_addr_to_pid = {}
    last_phys_addr = -1
    for phys_addr in sorted(addr_to_insns.keys()):
        if (last_phys_addr in addr_to_insns) and \
                (phys_addr == (last_phys_addr + 4 * len(new_contents[last_phys_addr]))):
            new_contents[last_phys_addr] = new_contents[last_phys_addr] + addr_to_insns[phys_addr]
            assert new_addr_to_pid[last_phys_addr] == addr_to_pid[phys_addr]
        else:
            last_phys_addr = phys_addr
            new_contents[last_phys_addr] = addr_to_insns[phys_addr]
            new_addr_to_pid[last_phys_addr] = addr_to_pid[phys_addr]

    for phys_addr in sorted(new_contents.keys()):
        if do_print:
            print("0x%016x: %4d" % (phys_addr, len(new_contents[phys_addr]),))
        total_decoded = 0
        byte_delta = 0
        for insn in new_contents[phys_addr]:
            if decoder.is_instruction(phys_addr + byte_delta, insn):
                total_decoded += 1
            byte_delta += 4
        if total_decoded == len(new_contents[phys_addr]):
            run_analyzer.analyze_insn_run(
                new_addr_to_pid[phys_addr],
                phys_addr,
                new_contents[phys_addr],
                decoder)
    run_analyzer.prune(decoder)
    run_analyzer.dump(decoder)
    decoder.dump()

def analyze_cache_contents():
    """Analyze cache contents."""
    parser = argparse.ArgumentParser("analyze cache contents")
    parser.add_argument(
        "--lb",
        help="lower bound on length of common runs",
        type=int,
        default=6,)
    parser.add_argument(
        "--ub",
        help="upper bound on length of common runs",
        type=int,
        default=30,)
    parser.add_argument(
        "rest",
        nargs=argparse.REMAINDER,)
    args = parser.parse_args()
    for input_file_name in args.rest:
        print("Reading %s" % (input_file_name,))
        with open(input_file_name, "r") as input_fd:
            consume_csv_file_analyze(input_fd, args.lb, args.ub)

if __name__ == "__main__":
    analyze_cache_contents()