#!  /usr/bin/python3

"""
Write a png file which highlights where spoecific instructions are.

"""
# pylint: disable=chained-comparison


import argparse
import csv
import re
import time

def run_combiner():
    parser = argparse.ArgumentParser("write png file showing location of instructions")
    parser.add_argument(
        "--insn",
        help="value of instruction to find",
        type=int,
        default=0x521f0000,)
    parser.add_argument(
        "rest",
        nargs=argparse.REMAINDER,)

    args = parser.parse_args()
    fieldnames = ["a", "b"] + ["d_%02d" % (i,) for i in range(0, 16)]
    for input_file_name in args.rest:
        with open(input_file_name, "r") as input_fd:
           print("open file %s" % (input_file_name,))
           reader = csv.DictReader(input_fd, fieldnames=fieldnames)
           for row in reader:
               for i in range(0, 16):
                   field = row["d_%02d" % (i,)]
                   # print(" %s" % (field,))
                   given = int(field, 16)
                   expect = args.insn
                   # print("%s %s 0x%08x vs 0x%08x\n" % (type(given), type(expect), given, expect,))
                   if given == expect:
                       print("1", end="")
                   else:
                       print(" ", end="")
               print("")

if __name__ == "__main__":
    run_combiner()

