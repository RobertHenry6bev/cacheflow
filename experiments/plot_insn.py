#!  /usr/bin/python3

"""
Write a png file which highlights where spoecific instructions are.
"""
import argparse
import csv

import png  # sudo apt-get install python3-pip ; pip3 install pypng

def plot_insn_bitmap():
    """Plot the L1 Cache as a bitmap."""
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

    with open("junk.png", "wb") as png_file:
        png_writer = png.Writer(16, 3*256, greyscale=True)

        fieldnames = ["a", "b"] + ["d_%02d" % (i,) for i in range(0, 16)]
        for input_file_name in args.rest:
            with open(input_file_name, "r") as input_fd:
                print("open file %s" % (input_file_name,))
                reader = csv.DictReader(input_fd, fieldnames=fieldnames)
                png_matrix = []
                for row in reader:
                    png_row = []
                    for i in range(0, 16):
                        field = row["d_%02d" % (i,)]
                        # print(" %s" % (field,))
                        given = int(field, 16)
                        expect = args.insn
                        if given == expect:
                            png_row.append(0xff)
                        else:
                            png_row.append(0x00)
                    png_matrix.append(png_row)
            png_writer.write(png_file, png_matrix)

if __name__ == "__main__":
    plot_insn_bitmap()
