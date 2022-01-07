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

    parser = argparse.ArgumentParser("plot process resident working sets")
    parser.add_argument(
        "--kind",
        help="kind of cache, either L1 or L2",
        type=str,
        default="L1",)
    parser.add_argument(
        "--period",
        help="sampling period",
        type=float,
        default="50.0",)
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

    timestamps = set()
    procname_to_timestamp_map = {}
    with open(input_file_name, "r") as input_fd:
        reader = csv.DictReader(input_fd)
        for row in reader:
            pid = int(row["pid"])
            if (1 < pid < 150):
                print("skip pid %d" % (pid,))
                continue
            if pid in pid_to_name.keys():
                procname = pid_to_name[pid]
            else:
                if pid not in [0, 1]:
                    continue
                procname = "-pid %d" % (pid,)  # starts - to sort < upper case

            if procname in [
                    "init",
                    #
                    "systemd",
                    "systemd-journald",
                    "systemd-resolved",
                    "systemd-networkd",
                    "systemd-timesyncd",
                    "sshd",
                    "multipathd",
                    "rsyslogd",
                    "packagekitd",
                    "snapd",
                    "sshd",
                    "fwupd",
                    #
                    "irqbalance",
                    "dbus-daemon",
                    "(sd-pam)",
                    "wpa_supplicant",
                    "python3",  # from unattended-upgrades and more
                    #
                    "sudo",
                    "sh",
                    "bash",
                    "vi",
                    "snapshot.x",  # the measuring tool
                    "e11_sleep.x",  # the measuring tool
              ]:
                print("skip procname %d %s" % (pid, procname,))
                continue

            timestamp = int(row["timestamp"])
            timestamps.add(timestamp)
            if procname not in procname_to_timestamp_map:
                procname_to_timestamp_map[procname] = {}
            if timestamp not in procname_to_timestamp_map[procname]:
                procname_to_timestamp_map[procname][timestamp] = {
                    "code": 0,
                    "data": 0,
                    }
            for kind in ["code", "data"]:
                procname_to_timestamp_map[procname][timestamp][kind] += \
                  int(row[kind])

    cache_number_lines = {}
    cache_number_lines["L1"] = 256
    cache_number_lines["L2"] = 16384

    timestamps = sorted(timestamps)

    kinds = [
      "code",
      "data",
      ]
    for kind in kinds:
        plt.rcParams["figure.figsize"] = (10, 7)
        plt.rcParams["figure.autolayout"] = True
        plt.subplots_adjust(bottom=0.30, top=0.95)
        for procname in sorted(procname_to_timestamp_map.keys()):
            datavals = []
            for timestamp in timestamps:
                try:
                    value = procname_to_timestamp_map[procname][timestamp][kind]
                except KeyError:
                    value = float("NaN")
                    if False:
                        print("missing: pid %d timestamp %d kind %s" % (
                            pid, timestamp, kind,))
                datavals.append(value)
            plt.plot(timestamps, datavals,
                label="%s %s" % (kind, procname,))

        plt.legend(loc="upper left")
        plt.title("%s Cache %s lines for various processes" % (
            args.kind, kind,))
        plt.xticks(rotation=90.0)
        plt.xlabel("timestamp (%gms per step [aspirational!])" % (args.period,))
        plt.ylabel("Cortex A72 %s cache lines (of %d)" % (
            args.kind,
            cache_number_lines[args.kind],))
        if "%s" in output_file_name:
            true_output_file_name = output_file_name % (kind,)
        else:
            true_output_file_name = output_file_name
        plt.savefig("%s" % (true_output_file_name,))
        plt.close()
        print("wrote %s" % (true_output_file_name,))

if __name__ == "__main__":
    analyze_workingsets_csv()
