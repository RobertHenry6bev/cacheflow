#! /usr/bin/python3
"""Analyze and plot table of workingsets from file workingsets.csv
as made by the Makefile:
   python3 analyze_processes.py data/*.csv > workingsets.csv

"""
import argparse
import csv

import matplotlib.pyplot as plt

import cachelib

def analyze_workingsets_csv():
    """Read from a csv file made by slowly analyzing all data/*.csv files,
    and determine the cache working set of each pid
    at each point in time."""

    parser = argparse.ArgumentParser("analyze process resident working sets")
    parser.add_argument(
        "--kind",
        help="kind of cache, either L1 or L2",
        type=str,
        default="L1",)
    parser.add_argument(
        "--input",
        help="name of input csv file holding reduced data from cachedumps",
        type=str,
        default="workingsets.csv",)
    parser.add_argument(
        "--output",
        help="name of output file name holding png",
        type=str,
        default="workingsets.png",)

    args = parser.parse_args()
    cache_info = cachelib.configuration_factory(args.kind)

    input_file_name = args.input
    output_file_name = args.output

    pid_to_name = cachelib.read_saved_command_info("./data")

    plt.rcParams["figure.figsize"] = (8, 7)
    plt.rcParams["figure.autolayout"] = True
    plt.subplots_adjust(bottom=0.30, top=0.95)

    timestamps = set()
    pid_to_timestamp_map = {}
    with open(input_file_name, "r") as input_fd:
        reader = csv.DictReader(input_fd)
        for row in reader:
            pid = int(row["pid"])
            if pid not in pid_to_timestamp_map:
                pid_to_timestamp_map[pid] = {}
            timestamp = int(row["timestamp"])
            #
            # if (timestamp < 125 or timestamp > 135):
            #   continue
            #
            timestamps.add(timestamp)
            if pid in pid_to_name:
                pid_to_timestamp_map[pid][timestamp] = {
                    "code": int(row["code"]),
                    "data": int(row["data"]),
                    }

    timestamps = sorted(timestamps)
    for pid in sorted(pid_to_name.keys()):
        if (1 < pid < 150) or pid_to_name[pid] in ["sshd:", "multipathd", "snapd", "sshd"]:
            print("skip pid %d %s" % (pid, pid_to_name[pid],))
            continue
        for kind in ["code", "data"]:
            datavals = []
            for timestamp in timestamps:
                try:
                    value = pid_to_timestamp_map[pid][timestamp][kind]
                except KeyError:
                    value = float("NaN")
                    if False:
                        print("missing: pid %d timestamp %d kind %s" % (
                            pid, timestamp, kind,))
                datavals.append(value)
            plt.plot(timestamps, datavals,
                label="%s pid %d %s" % (kind, pid, pid_to_name[pid],))

    plt.legend(loc="upper right")
    plt.title("%s Cache lines for various processes" % (args.kind,))
    plt.xticks(rotation=90.0)
    plt.xlabel("timestamp (10ms per step)")
    plt.ylabel("Cortex A72 %s cache lines" % (args.kind,))
    plt.savefig(output_file_name)
    plt.close()
    print("wrote %s" % (output_file_name,))

if __name__ == "__main__":
    analyze_workingsets_csv()
