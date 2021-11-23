#!  /usr/bin/python3

"""
Write a png file which highlights where spoecific instructions are.
"""

# pylint: disable=too-many-nested-blocks
# pylint: disable=too-many-locals

import argparse
import csv

import png  # sudo apt-get install python3-pip ; pip3 install pypng

class LineStats:
    """Statistics on a sequential run of instructions."""
    def __init__(self):
        self.map = {}
    def add(self, insns):
        """Add a run of instructions into our analysis."""
        if isinstance(insns, list):
            canon = ""
            sep = ""
            for insn in insns:
                canon += sep
                canon += "0x%08x" % (insn,)
                sep = ","
            insns = canon
        if insns not in self.map:
            self.map[insns] = 0
        self.map[insns] += 1
    def dump(self):
        """Dump ourself."""
        for insns, count in sorted(self.map.items(),
                reverse=True, key=lambda x:x[1]):
            print("%4d %s" % (count , insns,))

def plot_insn_bitmap():
    """Plot the L1 Cache as a bitmap."""
    parser = argparse.ArgumentParser("write png file with bitmap of found")
    parser.add_argument(
        "--insn",
        help="instruction to find",
        type=int,
        default=0x521f0000,)
    parser.add_argument(
        "--maxrows",
        help="maximum number of rows",
        type=int,
        default=3*256,)
    parser.add_argument(
        "--scale",
        help="png bits per logical pixel",
        type=int,
        default=4,)
    parser.add_argument(
        "--hit_only",
        help="only show hits in grey scale",
        action='store_true',
        default=False,)
    parser.add_argument(
        "--stats",
        help="dump statistics",
        action='store_true',
        default=False,)
    parser.add_argument(
        "--output",
        help="name of output file",
        type=str,
        default="junk.png",)
    parser.add_argument(
        "rest",
        nargs=argparse.REMAINDER,)

    args = parser.parse_args()

    simple_line_stats = LineStats()
    wayset_line_stats = {}
    for way in range(0, 3):
        for seti in range(0, 256):
            wayset_line_stats[(way, seti)] = LineStats()

    given_png_file_name = args.output
    for input_file_name in args.rest:
        print("Reading %s" % (input_file_name,))
        with open(input_file_name, "r") as input_fd:
            if given_png_file_name:
                png_file_name = given_png_file_name
            else:
                png_file_name = input_file_name.replace(".csv", ".png")
            if not png_file_name:
                consume_csv_file(input_fd, args, None,
                    simple_line_stats, wayset_line_stats)
            else:
                with open(png_file_name, "wb") as png_file:
                    consume_csv_file(input_fd, args, png_file,
                        simple_line_stats, wayset_line_stats)
    if args.stats:
        simple_line_stats.dump()
        for way in range(0, 3):
            for seti in range(0, 256):
                print("------------- %3d %3d" % (way, seti,))
                wayset_line_stats[(way, seti)].dump()

def consume_csv_file(input_fd, args, png_file,
      simple_line_stats, wayset_line_stats):
    """Read a csv file, possibliy writing a png_file, doing analysis."""
    fieldnames = ["way", "set"] + ["d_%02d" % (i,) for i in range(0, 16)]
    do_bw_match = args.hit_only
    search_insn = args.insn
    reader = csv.DictReader(input_fd, fieldnames=fieldnames)
    nrows = 0
    png_matrix = []
    for row in reader:
        if nrows >= args.maxrows:
            break
        wayset = (int(row["way"]), int(row["set"]))
        insns = [int(row["d_%02d" % (i,)], 16) for i in range(0, 16)]
        wayset_line_stats[wayset].add(insns)
        simple_line_stats.add(insns)
        for _y in range(0, args.scale):
            png_row = []
            for i in range(0, 16):
                insn = insns[i]
                for _x in range(0, args.scale):
                    if do_bw_match:
                        if insn == search_insn:
                            png_row.append(0xff)
                        else:
                            png_row.append(0x00)
                    else:
                        if insn == search_insn:
                            png_row.append(0xff)
                            png_row.append(0xff)
                            png_row.append(0xff)
                        else:
                            png_row.append((insn>>(0*8)) & 0xFF)
                            png_row.append((insn>>(1*8)) & 0xFF)
                            png_row.append((insn>>(2*8)) & 0xFF)
            png_matrix.append(png_row)
        nrows += 1
    if png_file:
        png_writer = png.Writer(
            args.scale*16,
            args.scale*args.maxrows,
            greyscale=do_bw_match)
        png_writer.write(png_file, png_matrix)

if __name__ == "__main__":
    plot_insn_bitmap()
