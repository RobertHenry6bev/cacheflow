#! /usr/bin/python3

"""
Write a png file which highlights where specific instructions are.

Also, if --stats flag is given, gather statistics describing dwell times.
"""

# pylint: disable=too-many-arguments
# pylint: disable=too-many-branches
# pylint: disable=too-many-locals
# pylint: disable=too-many-nested-blocks
# pylint: disable=too-many-statements

import argparse
import csv
import random

import png  # sudo apt-get install python3-pip ; pip3 install pypng

import cachelib

class LineStats:
    """Statistics on vectors of instruction, as from a single cache line
    holding 16 instructions.
    This is used to find dwell times,
    and other lifetime statistics.
    """
    def __init__(self):
        self.ivect_to_count = {}  # maps from instruction vector to count
        self.runlg_to_count = {}
        self.last_ivect = "xx"
        self.dwell_duration = -1
        self.nobservations = 0
        self.max_dwell_duration = 0
        self.max_dwell_insns = "xx"

    def add(self, insns):
        """Add a run of instructions into our analysis."""
        self.nobservations += 1
        assert isinstance(insns, list)
        insns = tuple(insns)
        if insns not in self.ivect_to_count:
            self.ivect_to_count[insns] = 0
        self.ivect_to_count[insns] += 1
        #
        # Manage runlengths (cache line did not appear to change contents)
        #
        if self.last_ivect == insns:
            self.dwell_duration += 1
            if self.dwell_duration > self.max_dwell_duration:
                self.max_dwell_duration = self.dwell_duration
                self.max_dwell_insns = insns
        else:
            if self.dwell_duration > 0:
                if self.dwell_duration not in self.runlg_to_count:
                    self.runlg_to_count[self.dwell_duration] = 0
                self.runlg_to_count[self.dwell_duration] += 1
            #
            self.last_ivect = insns
            self.dwell_duration = 1

    def dump(self, aggregate=None):
        """Dump ourself."""
        do_verbose = False
        if do_verbose:
            for insns, count in sorted(self.ivect_to_count.items(),
                    reverse=True, key=lambda x:x[1]):
                print("%4d %s" % (count , insns,))
        if do_verbose:
            print("max_dwell_duration=%d max_dwell=%s" % (
                self.max_dwell_duration, self.max_dwell_insns,))
        for dwell_duration, count in sorted(self.runlg_to_count.items(),
                reverse=True, key=lambda x:x[1]):
            print("dwell_duration=%3d count=%d" % (dwell_duration, count,))
            if aggregate is not None:
                if dwell_duration not in aggregate:
                    aggregate[dwell_duration] = 0
                aggregate[dwell_duration] += count

def plot_insn_bitmap():
    """Plot the L1 or L2 Cache as a bitmap."""
    parser = argparse.ArgumentParser("write png file with bitmap of found instructions")
    parser.add_argument(
        "--kind",
        help="kind of cache, either L1 or L2",
        type=str,
        default="L1",)
    parser.add_argument(
        "--insn",
        help="instruction to find",
        type=int,
        default=0xffffffff,
        )
    parser.add_argument(
        "--scale",
        help="png bits per logical pixel",
        type=int,
        default=4,)
    parser.add_argument(
        "--show_pid",
        help="color by pid",
        action='store_true',
        default=False,)
    parser.add_argument(
        "--grey_scale",
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
        help="name of output file (overrides inference from given filename)",
        type=str,
        default=None,)
    parser.add_argument(
        "rest",
        nargs=argparse.REMAINDER,)

    args = parser.parse_args()
    cache_info = cachelib.configuration_factory(args.kind)

    pid_color = {}
    pid_count = {}

    simple_line_stats = LineStats()

    wayset_line_stats = {}
    for cache_way in range(0, cache_info.get_nway()):
        for cache_set in range(0, cache_info.get_nset()):
            wayset_line_stats[(cache_way, cache_set,)] = LineStats()

    given_png_file_name = args.output
    for input_file_name in args.rest:
        print("Reading %s" % (input_file_name,))
        with open(input_file_name, "r") as input_fd:
            if given_png_file_name:
                png_file_name = given_png_file_name
            else:
                png_file_name = input_file_name.replace(".csv", ".png")
            if not png_file_name:
                consume_csv_file(cache_info, input_fd, args, None,
                    pid_color, pid_count,
                    simple_line_stats, wayset_line_stats)
            else:
                with open(png_file_name, "wb") as png_file:
                    print("Writing %s" % (png_file_name,))
                    consume_csv_file(cache_info, input_fd, args, png_file,
                        pid_color, pid_count,
                        simple_line_stats, wayset_line_stats)

    if args.stats:
        print("Start simple_line_stats {")
        simple_line_stats.dump()
        print("End   simple_line_stats }")

        aggregate = {}  # map from dwell duration to count
        print("Start wayset_line_stats {")
        for cache_way in range(0, cache_info.get_nway()):
            for cache_set in range(0, cache_info.get_nset()):
                print("------------- Stats for cache_way %3d set %3d" % (cache_way, cache_set,))
                wayset_line_stats[(cache_way, cache_set,)].dump(aggregate)
        print("End   wayset_line_stats }")
        for dwell_duration, count in sorted(aggregate.items()):
            print("%3d: %3d" % (dwell_duration, count,))

def consume_csv_file(cache_info, input_fd, args, png_file,
      pid_color, pid_count,
      simple_line_stats, wayset_line_stats):
    """Read a csv file, possibliy writing a png_file, doing analysis."""
    reader = csv.DictReader(input_fd, cache_info.get_field_names())
    #
    # Read all rows, and store internally,
    # so we can display the image with cache_info.get_nway()S ways going left to right.
    #
    contents = {}
    pids = {}
    for row in reader:
        wayset = (int(row["way"]), int(row["set"]),)
        insns = [int(row["d_%02d" % (i,)], 16) for i in range(0, 16)]
        contents[wayset] = insns
        wayset_line_stats[wayset].add(insns)
        simple_line_stats.add(insns)
        pid = int(row["pid"])
        pids[wayset] = pid

    do_show_pid = args.show_pid
    do_grey_scale = args.grey_scale
    search_insn = args.insn
    #
    do_blue = False
    do_green = False
    #
    png_matrix = []
    xwidth = 0
    for cache_set in range(0, cache_info.get_nset()):
        for _y in range(0, args.scale):
            xwidth = 0
            png_row = []
            for cache_way in range(0, cache_info.get_nway()):
                #
                # Draw a vertical blue bar at the left end
                #
                if do_blue:
                    for _x in range(0, args.scale):
                        if do_grey_scale:
                            png_row.append(0xff)
                        else:
                            png_row.append(0x00)
                            png_row.append(0x00)
                            png_row.append(0xff)
                        xwidth += 1
                #
                wayset = (cache_way, cache_set,)
                insns = contents[wayset]
                pid = pids[wayset]
                if pid not in pid_count:
                    pid_count[pid] = 0
                pid_count[pid] += 1
                if pid not in pid_color:
                    if pid in [0, -1]:
                        pid_color[pid] = [0, 0, 0]
                    else:
                        pid_color[pid] = [
                            random.randint(0, 255),
                            random.randint(0, 255),
                            random.randint(0, 255),
                        ]
                offset = 1
                for base in range(0, 16, 4):
                    i = base + offset  # just look for the search insn
                    insn = insns[i]
                    # print("i=%4d insn=0x%08x search_insn=0x%08x" % (i, insn, search_insn,))
                    for _x in range(0, args.scale):
                        match = (insn == search_insn)
                        if do_grey_scale:
                            if match:
                                png_row.append(0xff)
                                xwidth += 1
                            else:
                                png_row.append(0x00)
                                xwidth += 1
                        else:
                            if match:
                                png_row.append(0xff)  # white
                                png_row.append(0xff)  # white
                                png_row.append(0xff)  # white
                                xwidth += 1
                            else:
                                if do_show_pid:
                                    png_row.append(pid_color[pid][0])
                                    png_row.append(pid_color[pid][1])
                                    png_row.append(pid_color[pid][2])
                                else:
                                    png_row.append((insn>>(0*8)) & 0xFF)  # gibberish
                                    png_row.append((insn>>(1*8)) & 0xFF)  # gibberish
                                    png_row.append((insn>>(2*8)) & 0xFF)  # gibberish
                                xwidth += 1
                if do_green:
                    #
                    # Draw a vertical green bar at the right end
                    #
                    for _x in range(0, args.scale):
                        if do_grey_scale:
                            png_row.append(0xff)
                        else:
                            png_row.append(0x00)
                            png_row.append(0xff)
                            png_row.append(0x00)
                        xwidth += 1
            png_matrix.append(png_row)

    for pid, count in sorted(pid_count.items(), reverse=True, key=lambda x:x[1]):
        print("pid %6d count %8d color=%s" % (pid, count, pid_color[pid]))
    if png_file:
        # print("xwidth=%d XXX do_grey_scale %s" % (xwidth, do_grey_scale,))
        png_writer = png.Writer(
            xwidth,
            args.scale*cache_info.get_nset(),
            greyscale=do_grey_scale)
        png_writer.write(png_file, png_matrix)

if __name__ == "__main__":
    plot_insn_bitmap()
