#!/usr/bin/env python3
"""Fit the paper's marginal-cost model to a board_sweep.py CSV.

For every (app, impl) present: a three-point affine fit C = a + b*B per
regime (small = the three smallest payloads, large = the three largest),
slope beta in cycles/byte, with the 3-point-vs-2-point-chord check the
paper's gate uses (<= 5%). Speedups are against the app's S1 row (hw_s1 /
s1) in the SAME CSV -- same image, same software build. Also prints the
sw-versus-rori S0 comparison for ChaCha when both are present.

  python3 tests/crypto/board_fit.py docs/proposals/data/board-u7-20260904.csv
"""
import csv, sys, collections

S1 = {"aes_gcm": "hw_s1", "chacha_poly": "s1"}

def fit(points):                       # points: [(bytes, cycles_med)], len 3
    xs = [p[0] for p in points]; ys = [p[1] for p in points]; n = len(xs)
    mx, my = sum(xs)/n, sum(ys)/n
    b = sum((x-mx)*(y-my) for x, y in zip(xs, ys)) / sum((x-mx)**2 for x in xs)
    a = my - b*mx
    chord = (ys[-1]-ys[0]) / (xs[-1]-xs[0])
    return a, b, chord

def main(path):
    rows = list(csv.DictReader(open(path)))
    by = collections.defaultdict(list)
    for r in rows:
        by[(r["app"], r["impl"])].append((int(r["bytes"]), int(r["cycles_med"]), int(r["instrs"])))
    res = {}
    for key, pts in sorted(by.items()):
        pts.sort()
        out = {}
        for name, sel in (("small", pts[:3]), ("large", pts[-3:])):
            if len(sel) < 3 or len(pts) < 6: continue
            a, b, chord = fit([(x, y) for x, y, _ in sel])
            dev = abs(b/chord - 1)*100
            ib = fit([(x, i) for x, _, i in sel])[1]
            out[name] = (a, b, chord, dev, ib)
        res[key] = out
    print(f"{'app':<12}{'impl':<10}{'regime':<7}{'c/B':>8}{'chord':>8}{'dev%':>6}{'i/B':>8}{'x S1':>7}{'intercept(k)':>13}")
    for (app, impl), out in res.items():
        for regime, (a, b, chord, dev, ib) in out.items():
            s1 = res.get((app, S1[app]), {}).get(regime)
            sp = f"{s1[1]/b:6.2f}" if s1 else "     -"
            flag = "" if dev <= 5 else "  <-- >5% off chord"
            print(f"{app:<12}{impl:<10}{regime:<7}{b:8.3f}{chord:8.3f}{dev:6.1f}{ib:8.3f}{sp:>7}{a/1000:13.1f}{flag}")
    sw, ro = res.get(("chacha_poly", "sw")), res.get(("chacha_poly", "rori"))
    if sw and ro:
        for regime in ("small", "large"):
            if regime in sw and regime in ro:
                print(f"ChaCha S0 on silicon, {regime}: sw {sw[regime][1]:.3f} vs rori {ro[regime][1]:.3f} c/B "
                      f"-> sw is {100*(sw[regime][1]/ro[regime][1]-1):+.1f}%")

if __name__ == "__main__":
    main(sys.argv[1])
