#!/usr/bin/env python3

from collections import defaultdict
from os import path, sys, walk
from datetime import datetime, timedelta

ROOT_FOLDER = "results"

bots = defaultdict(lambda: defaultdict(list))

def parseDate(val):
    for fmt in ("%Y-%m-%d", "%Y-%m-%d-%H"):
        try:
            return datetime.strptime(val, fmt)
        except ValueError:
            pass
    raise ValueError("{} is no valid datetime".format(val))

def parseEntry(e, ts):
    global bots

    ip, botId = e.strip().split(" ")
    bots[botId][ip].append(ts)


def parseFile(fi):
    global timestamps

    parts = fi.split("_")
    ts = datetime.strptime("{} {}".format(parts[1],
        parts[2][:-4]), "%Y-%m-%d %H-%M") + timedelta(hours=1)

    with open(path.join(ROOT_FOLDER, fi), "r") as fp:
        entries = fp.readlines()
    
    for e in entries:
        parseEntry(e, ts)


def writePlot(start, end):
    print("ts, avg, min, max, total_avg")
    counts = defaultdict(int)
    for b, tup in bots.items():
        for ip, tses in tup.items():
            for ts in tses:
                if ts > start and ts < end:
                    counts[ts] += 1

    total = counts.values()
    totalAvg = sum(total)/len(total)
    for h in range(23):
        for m in range(0, 60, 15):
            vals = [c for ts, c in counts.items() if ts.hour == h and ts.minute == m]
            print("2017-11-12 {:02d}:{:02d}, {}, {}, {}, {}".format(h, m, sum(vals)/len(vals), min(vals), max(vals), totalAvg))


def writeStatistics(verbose):
    ips = 0
    for b, tup in bots.items():
        print(b)
        for ip, tses in sorted(tup.items()):
            print("->", ip)
            ips += 1
            if verbose:
                for ts in sorted(tses):
                    print("-->", ts)
    print("{} nodes total with {} unique IPs".format(len(bots), ips))


def main():
    for _, __, files in walk(ROOT_FOLDER):
        for fi in files:
            parseFile(fi)

    if len(sys.argv) > 1:
        if sys.argv[1] == "plot":
            if len(sys.argv) == 4:
                start = parseDate(sys.argv[2])
                end = parseDate(sys.argv[3])
                end += timedelta(24 - end.hour)
                writePlot(start, end)
                return
            else:
                print("plot subcommand requires two date arguments")
                return
        elif sys.argv[1] == "short":
            writeStatistics(False)
            return

    writeStatistics(True)

if __name__ == "__main__":
    main()
