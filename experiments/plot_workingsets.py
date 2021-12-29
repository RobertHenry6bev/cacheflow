#! /usr/bin/python3
"""Analyze and plot table of workingsets from workingsets.csv
as made by
   python3 analyze_processes.py data/*.csv > workingsets.csv

"""

import argparse
import csv
import re
import matplotlib.pyplot as plt

def analyze_workingsets_csv():
    output_file_name = "workingsets.png"
    input_file_name = "workingsets.csv"
    pidset = set([
      0,
      20251,
      # 18788,
      20437,
      ])
    pid_to_name = {0: "kernel", 20251: "teche", 18788: "postgres", 20437: "unknown"}

    plt.rcParams["figure.figsize"] = (8, 7)
    plt.rcParams["figure.autolayout"] = True
    plt.subplots_adjust(bottom=0.30, top=0.95)

    timestamps = set()
    pid_to_timestamp_map = {}
    xitems = []
    with open(input_file_name, "r") as input_fd:
        reader = csv.DictReader(input_fd)
        for row in reader:
            pid = int(row["pid"])
            if pid not in pid_to_timestamp_map:
                pid_to_timestamp_map[pid] = {}
            timestamp = int(row["timestamp"])
            timestamps.add(timestamp)
            if pid in pidset:
                pid_to_timestamp_map[pid][timestamp] = {"code": int(row["code"]), "data": int(row["data"])}
    timestamps = sorted(timestamps)
    for pid in sorted(pidset):
        for kind in ["code", "data"]:
            datavals = []
            for timestamp in timestamps:
                datavals.append(pid_to_timestamp_map[pid][timestamp][kind])
            plt.plot(timestamps, datavals, label="%s pid %d %s" % (kind, pid, pid_to_name[pid],))
    plt.legend(loc="upper right")
    plt.title("L2 Cache lines for various processes")
    plt.xticks(rotation=90.0)
    plt.xlabel("timestamp")
    plt.ylabel("cache lines")
    plt.savefig(output_file_name)
    plt.close()
    print("wrote %s" % (output_file_name,))

if __name__ == "__main__":
    analyze_workingsets_csv()
