#! /usr/bin/python3

"""
Analyze experiments/data/cachedump*.csv files and extract working set sizes of all of the processes.
Extract other information
"""

import argparse
import csv
import re

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

class PidInfo:
    """Holds information about a particular pid."""
    def __init__(self, timestep, pid):
        self.timestep = timestep
        self.pid = pid
        self.code_rows = 0
        self.data_rows = 0
    def fieldnames():
        return "timestamp,pid,code,data"
    def __str__(self):
        return "%8d, %7d, %5d, %5d" % (self.timestep, self.pid, self.code_rows, self.data_rows,)

def analyze_processes():
    """Analyze processes working sets in the cache"""
    parser = argparse.ArgumentParser("analyze process resident working sets")
    parser.add_argument(
        "rest",
        nargs=argparse.REMAINDER,)

    args = parser.parse_args()

    print(PidInfo.fieldnames(), flush=True)
    for input_file_name in args.rest:
        with open(input_file_name, "r") as input_fd:
            try:
                analyze_processes_file(input_file_name, input_fd)
            except TypeError as our_error:
                pass

RE_FILENAME = re.compile(r'[^0-9]+([0-9]+)\.csv')
def analyze_processes_file(input_file_name, input_fd):
    """Read a csv file, doing analysis."""
    match = RE_FILENAME.match(input_file_name)
    assert match
    timestep = int(match.group(1), 10)
    reader = csv.DictReader(input_fd, fieldnames=FIELD_NAMES)
    #
    # Read all rows, and store internally,
    # so we can display the image with NWAYS ways going left to right.
    #
    pidinfo = {}  # indexed by phys_addr of PidInfo
    for row in reader:
        pid = int(row["pid"])
        if pid not in pidinfo:
            pidinfo[pid] = PidInfo(timestep, pid)
        phys_addr = int(row["phys_addr"], 16)
        insns = [int(row["d_%02d" % (i,)], 16) for i in range(0, 16)]

        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        byte_delta = 0
        ndecoded = 0
        decoded_insns = []
        for content in insns:
            for insn in md.disasm(content.to_bytes(4, 'little'), phys_addr + byte_delta):
                ndecoded += 1
                decoded_insns.append("%s\t%s" % (insn.mnemonic, insn.op_str,))
            byte_delta += 4
        if False:
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
