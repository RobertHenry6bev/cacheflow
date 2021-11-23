#!  /usr/bin/python3

"""
Write a png file which highlights where spoecific instructions are.
"""
import argparse
import csv

import png  # sudo apt-get install python3-pip ; pip3 install pypng

def plot_insn_bitmap():
    """Plot the L1 Cache as a bitmap."""
    parser = argparse.ArgumentParser("write png file with bitmap of found")
    parser.add_argument(
        "--insn",
        help="value of the instruction to find",
        type=int,
        default=0x521f0000,)
    parser.add_argument(
        "--maxrows",
        help="maximum number of rows",
        type=int,
        default=32,)
    parser.add_argument(
        "--scale",
        help="png bits per logical pixel",
        type=int,
        default=4,)
    parser.add_argument(
        "--hit_only",
        help="only show hits in grey scale",
        type=bool,
        default=True,)
    parser.add_argument(
        "--output",
        help="name of output file",
        type=str,
        default="junk.png",)
    parser.add_argument(
        "rest",
        nargs=argparse.REMAINDER,)

    args = parser.parse_args()
    do_bw_match = args.hit_only

    with open(args.output, "wb") as png_file:
        png_writer = png.Writer(
            args.scale*16,
            args.scale*args.maxrows,
            greyscale=do_bw_match)
        # fieldnames = ["a", "b"] + ["d_%02d" % (i,) for i in range(0, 16)]
        fieldnames = ["d_%02d" % (i,) for i in range(0, 16)]
        for input_file_name in args.rest:
            with open(input_file_name, "r") as input_fd:
                reader = csv.DictReader(input_fd, fieldnames=fieldnames)
                nrows = 0
                png_matrix = []
                for row in reader:
                    if nrows >= args.maxrows:
                        break
                    for _y in range(0, args.scale):
                        png_row = []
                        for i in range(0, 16):
                            # print("row=%s" % (row,))
                            field_value = int(row["d_%02d" % (i,)], 16)
                            search_value = args.insn
                            for _x in range(0, args.scale):
                                if do_bw_match:
                                    if field_value == search_value:
                                        png_row.append(0xff)
                                    else:
                                        png_row.append(0x00)
                                else:
                                    png_row.append((field_value>>(0*8)) & 0xFF)
                                    png_row.append((field_value>>(1*8)) & 0xFF)
                                    png_row.append((field_value>>(2*8)) & 0xFF)
                        png_matrix.append(png_row)
                    nrows += 1
            png_writer.write(png_file, png_matrix)

if __name__ == "__main__":
    plot_insn_bitmap()
