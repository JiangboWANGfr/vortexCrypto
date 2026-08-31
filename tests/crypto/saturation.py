#!/usr/bin/env python3
"""Pick the message count at which every implementation saturates the machine.

    saturation.py [records.csv]

Reads a bench.py records.csv (default build32/crypto_runs/saturation/records.csv,
normally produced from tests/crypto/saturation.yaml) and prints two tables.

The first is per (app, build, impl, blocks_per_msg), one line per message
count: cycles/B over the whole run, and balance -- min/max of the per-core
MINSTRET split, where 1.00 is even and a lane-mapped kernel with fewer
messages than threads shows ~0. Balance is the saturation gate. The raw
cycles/B level is reference only: it keeps falling with n as launch overhead
amortises, so it never plateaus cleanly.

The second is the marginal slope -- Delta cycles over Delta bytes across the
b points at one n -- which is the metric the measurement matrix reports; its
intercept absorbs launch and per-message cost. The step column is the change
against the previous doubling of n. Slope drift past the balanced n is
cache/DRAM regime moving with the working set, which the matrix handles by
fitting each regime pair separately within one n; it is not a reason to keep
raising n.

The verdict per app is the smallest n at which every (build, impl, b) shows
balance >= 0.90. Measure the whole matrix at that n, so no comparison mixes
core utilisations. The 2026-08 sweep's answer was n=128 for both apps.

A build is one distinct `extensions` string; the same impl measured in two
builds (s1 anchors the sg16 build as well as the all-on one) stays two rows.
"""

import csv
import os
import sys

BALANCE_FLOOR = 0.90


def balance(core_instrs):
    """min/max of the colon-separated per-core MINSTRET field, or None when a
    record predates the field."""
    if not core_instrs:
        return None
    parts = [int(p) for p in core_instrs.split(":")]
    return (min(parts) / max(parts)) if max(parts) else 0.0


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "build32", "crypto_runs", "saturation", "records.csv")
    groups = {}  # (app, ext, impl, b) -> {n: row}; a rerun of a point wins
    with open(path) as fh:
        for row in csv.DictReader(fh):
            key = (row["app"], row["extensions"], row["impl"],
                   int(row["blocks_per_msg"]))
            groups.setdefault(key, {})[int(row["msgs"])] = row

    # Build tag: index of the extensions string among the app's, sorted.
    exts = {}
    for app, ext, _, _ in groups:
        exts.setdefault(app, set()).add(ext)
    bld = {(app, e): i for app in exts for i, e in enumerate(sorted(exts[app]))}

    balanced_ns = {}  # app -> [set of balanced n per (build, impl, b)]
    print("{:<12} {:>3} {:<10} {:>3} {:>5} {:>9} {:>8}".format(
        "app", "bld", "impl", "b", "n", "cycles/B", "balance"))
    for (app, ext, impl, b), by_n in sorted(groups.items()):
        ok_ns = set()
        for n in sorted(by_n):
            row = by_n[n]
            cpb = int(row["cycles"]) / int(row["bytes"])
            bal = balance(row.get("core_instrs", ""))
            if bal is not None and bal >= BALANCE_FLOOR:
                ok_ns.add(n)
            print("{:<12} {:>3} {:<10} {:>3} {:>5} {:>9.3f} {:>8}".format(
                app, bld[(app, ext)], impl, b, n, cpb,
                "?" if bal is None else "{:.2f}".format(bal)))
        balanced_ns.setdefault(app, []).append(ok_ns)

    print()
    print("{:<12} {:>3} {:<10} {:>5} {:>11} {:>7}".format(
        "app", "bld", "impl", "n", "slope c/B", "step"))
    slopes = {}  # (app, ext, impl, n) -> {b: (cycles, bytes)}
    for (app, ext, impl, b), by_n in groups.items():
        for n, row in by_n.items():
            slopes.setdefault((app, ext, impl, n), {})[b] = (
                int(row["cycles"]), int(row["bytes"]))
    prev = {}
    for (app, ext, impl, n), by_b in sorted(slopes.items()):
        if len(by_b) < 2:
            continue
        (c_lo, d_lo), (c_hi, d_hi) = by_b[min(by_b)], by_b[max(by_b)]
        slope = (c_hi - c_lo) / (d_hi - d_lo)
        last = prev.get((app, ext, impl))
        print("{:<12} {:>3} {:<10} {:>5} {:>11.4f} {:>7}".format(
            app, bld[(app, ext)], impl, n, slope,
            "" if last is None else "{:+.1%}".format((slope - last) / last)))
        prev[(app, ext, impl)] = slope

    print()
    for app, sats in sorted(balanced_ns.items()):
        common = set.intersection(*sats) if sats else set()
        print("{}: {}".format(app, "measure at n={}".format(min(common))
                              if common else
                              "no n balances every (build, impl, b) -- sweep further"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
