#! /usr/bin/python3

"""
Analyze experiments/data/cachedump*.csv files and extract working set
sizes of all of the processes

This writes another csv file, which is read by the plotter
from plot_workingsets.py
"""
# pylint: disable=too-many-locals

import argparse
import csv
import re

import capstone

import cachelib

DEBUG = False

class PidInfo:
    """Holds information about a particular pid."""
    def __init__(self, timestep, pid):
        self.timestep = timestep
        self.pid = pid
        self.code_rows = 0
        self.data_rows = 0
    @classmethod
    def fieldnames(cls):
        """Return a CSV header snippet."""
        _ = cls
        return "timestamp,pid,code,data"
    def __str__(self):
        return "%8d, %7d, %5d, %5d" % (self.timestep, self.pid, self.code_rows, self.data_rows,)

def analyze_processes():
    """Analyze processes working sets in the cache"""
    parser = argparse.ArgumentParser("analyze process resident working sets")
    parser.add_argument(
        "--kind",
        help="kind of cache, either L1 or L2",
        type=str,
        default="L1",)
    parser.add_argument(
        "rest",
        nargs=argparse.REMAINDER,)

    args = parser.parse_args()
    cache_info = cachelib.configuration_factory(args.kind)

    print(PidInfo.fieldnames(), flush=True)
    for input_file_name in args.rest:
        with open(input_file_name, "r") as input_fd:
            try:
                analyze_processes_file(cache_info, input_file_name, input_fd)
            except TypeError:
                pass

RE_FILENAME = re.compile(r'[^0-9]+([12])\.([0-9]+)\.csv')
def analyze_processes_file(cache_info, input_file_name, input_fd):
    """Read a csv file, doing analysis."""
    match = RE_FILENAME.match(input_file_name)
    assert match
    _cache_number = int(match.group(1), 10)
    timestep = int(match.group(2), 10)
    reader = csv.DictReader(input_fd, fieldnames=cache_info.get_field_names())
    #
    # Read all rows, and store internally
    #
    pidinfo = {}  # indexed by phys_addr of PidInfo
    for row in reader:
        pid = int(row["pid"])
        if pid not in pidinfo:
            pidinfo[pid] = PidInfo(timestep, pid)
        phys_addr = int(row["phys_addr"], 16)
        insns = [int(row["d_%02d" % (i,)], 16) for i in range(0, 16)]

        capstone_engine = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        byte_delta = 0
        ndecoded = 0
        decoded_insns = []
        for content in insns:
            for insn in capstone_engine.disasm(
                    content.to_bytes(4, 'little'), phys_addr + byte_delta):
                ndecoded += 1
                decoded_insns.append("%s\t%s" % (insn.mnemonic, insn.op_str,))
            byte_delta += 4
        if DEBUG:
            print("Address 0x%016x has %2d instructions: %s" % (phys_addr, ndecoded, insns,))
            if ndecoded == 16:
                for decoded_insn in decoded_insns:
                    print("\t%s" % (decoded_insn,))
        if ndecoded == 16:
            pidinfo[pid].code_rows += 1
        else:
            pidinfo[pid].data_rows += 1
    for _pid, info in pidinfo.items():
        print("%s" % (info,), flush=True)

if __name__ == "__main__":
    analyze_processes()
