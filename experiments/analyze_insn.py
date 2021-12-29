#! /usr/bin/python3

"""
Analyze data held in cache looking for many things.
"""

import argparse
import csv

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

def consume_csv_file_analyze(input_fd):
    """Read a csv file, doing analysis."""

    reader = csv.DictReader(input_fd, fieldnames=FIELD_NAMES)
    #
    # Read all rows, and store internally,
    # so we can display the image with NWAYS ways going left to right.
    #
    contents = {}  # indexed by phys_addr
    for row in reader:
        phys_addr = int(row["phys_addr"], 16)
        insns = [int(row["d_%02d" % (i,)], 16) for i in range(0, 16)]
        contents[phys_addr] = insns

    new_contents = {}
    last_phys_addr = -1
    for phys_addr in sorted(contents.keys()):
        if (last_phys_addr in contents) and \
                (phys_addr == (last_phys_addr + 4 * len(new_contents[last_phys_addr]))):
            new_contents[last_phys_addr] = new_contents[last_phys_addr] + contents[phys_addr]
        else:
            last_phys_addr = phys_addr
            new_contents[last_phys_addr] = contents[phys_addr]
    for phys_addr in sorted(new_contents.keys()):
        print("0x%016x: %4d" % (phys_addr, len(new_contents[phys_addr]),))

if __name__ == "__main__":
    analyze_cache_contents()
