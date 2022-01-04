#! /usr/bin/python3

"""
Analyze data held in cache looking for long runs of instructions
that span many 16-instruction wide cache lines.
#
This is/was used to find duplicate instruction strings in the cache.
"""

# pylint: disable=consider-using-enumerate
# pylint: disable=too-many-arguments
# pylint: disable=too-many-branches
# pylint: disable=too-many-locals
# pylint: disable=no-self-use

import argparse
import csv
import os
import re

import capstone

import cachelib

class RunCountAccumulator:
    """This is an accumulator when counting run frequency."""
    def __init__(self):
        self.count = 0
        self.pids = []
        self.addrs = []

    def __str__(self):
        return "{%d, %s, %s}" % (self.count, self.pids, ["0x%016x" % (x,) for x in self.addrs],)

    def incr(self, _key, pid, addr):
        """Increment ourselves"""
        self.count += 1
        self.pids.append(pid)
        self.addrs.append(addr)

    def decr(self, key, pid, addr):
        """Decrement ourselves.  I never got this to work; historical only"""
        print("decr key=%s pid=%d addr=0x%016x count=%d len=%d" % (
            key, pid, addr, self.count, len(self.pids),))
        assert len(self.pids) == len(self.addrs)
        assert len(self.pids) == self.count
        if self.count > 0:
            for i in range(0, len(self.pids)):
                if (self.pids[i] == pid) and (self.addrs[i] == addr):
                    self.count -= 1
                    self.pids.pop(i)
                    self.addrs.pop(i)
                    return
            print("decr did not find pid %d and addr 0x%016x" % (pid, addr,))

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
        do_debug = True
        if do_debug:
            self.print_insn_run(pid, phys_addr, insns, decoder)
        self._process_insn_run(pid, phys_addr, insns, decoder, self.lg_lb, self.lg_ub, True)

    def _process_insn_run(self, pid, phys_addr, insns, _decoder, xlg_lb, xlg_ub, incr):
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

    def dump(self, decoder, pidmap):
        """Dump out the instruction runs."""
        last_len = 0
        rangekill = set()
        # sort by descending length of run
        for insn_slice, accum in sorted(self.runcount.items(),
                reverse=True, key=lambda x: 100*len(x[0])+x[1].count):
            if last_len != len(insn_slice):
                last_len = len(insn_slice)
                print("")
            if accum.count <= 1:
                continue
            nuniques = 0
            for i in range(0, accum.count):
                phys_addr = accum.addrs[i]
                span = set(range(phys_addr, phys_addr + 4 * len(insn_slice)))
                if len(rangekill & span):
                    continue
                rangekill.update(span)
                nuniques += 1
            if nuniques != accum.count:
                continue

            do_single_line = False
            if do_single_line:
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
                     accum.count,
                     len(insn_slice),
                     accum.pids,
                     ["0x%016x" % (addr,) for addr in accum.addrs],
                     ["0x%08x" % (insn,) for insn in insn_slice],
                     decode,
                     ))
            else:
                for i in range(0, len(insn_slice)):
                    for j in range(0, len(accum.addrs)):
                        phys_addr = accum.addrs[j] + i * 4
                        print("%5d %8s 0x%016x " % (accum.pids[j], pidmap[accum.pids[j]], phys_addr,), end="")
                    print("0x%08x %s" % (
                        insn_slice[i], decoder.decode_to_str(phys_addr, insn_slice[i]),))
                print("")

def consume_csv_file_analyze(cache_info, input_fd, pidmap, lg_lb, lg_ub):
    """Read a csv file, doing analysis."""
    do_print = False
    do_skip_pid0 = True
    run_analyzer = InsnRunAnalyzer(lg_lb, lg_ub)
    decoder = cachelib.InstructionDecoder()

    reader = csv.DictReader(input_fd, fieldnames=cache_info.get_field_names())
    #
    # Read all rows, and store internally,
    # so we can display the image with cachelib.NWAYS ways going left to right.
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
            if new_addr_to_pid[last_phys_addr] != addr_to_pid[phys_addr]:
                # This was an assert for L2 land TODO(robhenry)
                print("new_addr_to_pid[0x%x] = %d != addr_to_pid[0x%x] = %d" % (
                  last_phys_addr, new_addr_to_pid[last_phys_addr],
                  phys_addr, addr_to_pid[phys_addr],))
        else:
            last_phys_addr = phys_addr
            new_contents[last_phys_addr] = addr_to_insns[phys_addr]
            new_addr_to_pid[last_phys_addr] = addr_to_pid[phys_addr]

    for phys_addr in sorted(new_contents.keys()):
        if True or do_print:
            print("0x%016x: %4d" % (phys_addr, len(new_contents[phys_addr]),))
        total_decoded = 0
        byte_delta = 0
        for insn in new_contents[phys_addr]:
            if decoder.is_instruction(phys_addr + byte_delta, insn):
                total_decoded += 1
            byte_delta += 4
        print("total_decoded=%d" % (total_decoded,))
        if total_decoded == len(new_contents[phys_addr]):
            run_analyzer.analyze_insn_run(
                new_addr_to_pid[phys_addr],
                phys_addr,
                new_contents[phys_addr],
                decoder)
    run_analyzer.dump(decoder, pidmap)
    decoder.dump()

def analyze_cache_contents():
    """Analyze cache contents."""
    parser = argparse.ArgumentParser("analyze cache contents")
    parser.add_argument(
        "--kind",
        help="kind of cache, either L1 or L2",
        type=str,
        default="L1",)
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
    cache_info = cachelib.configuration_factory(args.kind)
    pidmap = cachelib.read_saved_command_info("./data")
    for input_file_name in args.rest:
        print("Reading %s" % (input_file_name,))
        with open(input_file_name, "r") as input_fd:
            consume_csv_file_analyze(cache_info, input_fd, pidmap, args.lb, args.ub)

if __name__ == "__main__":
    analyze_cache_contents()
