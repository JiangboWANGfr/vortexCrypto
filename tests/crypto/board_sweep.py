#!/usr/bin/env python3
"""U7 board sweep: run one crypto app on the DE10-Pro over a matrix of
(impl, blocks_per_msg), gate every run the way bench.py does, and record the
median / IQR of cycles over N runs after W warm-ups.

  python3 tests/crypto/board_sweep.py --app aes_gcm --impls 0,1,8 \
      --blocks 2,4,8,64,128,256 --bitstream combined --out board.csv

Gates per run: exit 0, PASSED!, exactly one *_PERF line, per-core balance
(min/max core_instrs) >= 0.99. Instruction counts must be identical across
all runs of a point (they are deterministic); a mismatch aborts the point.
The app must already be built for the bitstream's configuration -- this
script never rebuilds. Raw outputs go to <out>.logs/. Never kill a run
mid-DMA: the DMA engine on this host only recovers by reboot.
"""
import argparse, csv, os, re, statistics, subprocess, sys, time, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PERF = re.compile(r"^(?P<app>[A-Z_]+)_PERF: (?P<kv>.*)$", re.M)

def git_stamp():
    try:
        return subprocess.check_output(["git", "-C", ROOT, "describe", "--always", "--dirty"],
                                       text=True).strip()
    except Exception:
        return "?"

# A hang (timeout) means the device DMA is likely wedged; the caller aborts
# the whole sweep rather than SIGKILL-and-continue, which on this host would
# leave the DMA engine dead. HANG is signalled by returning ("HANG", msg).
def run_once(binary, cwd, opts, env, log, per_run_timeout):
    try:
        p = subprocess.run([binary] + opts, cwd=cwd, env=env, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=per_run_timeout)
    except subprocess.TimeoutExpired as e:
        log.write(f"$ {os.path.basename(binary)} {' '.join(opts)}\n"
                  f"[HANG > {per_run_timeout}s]\n{e.output or ''}\n")
        return "HANG", f"no response in {per_run_timeout}s"
    log.write(f"$ {os.path.basename(binary)} {' '.join(opts)}\n{p.stdout}\n")
    perfs = PERF.findall(p.stdout)
    if p.returncode != 0:            return None, f"exit {p.returncode}"
    if "PASSED!" not in p.stdout:    return None, "no PASSED!"
    if len(perfs) != 1:              return None, f"{len(perfs)} PERF lines"
    kv = dict(tok.split("=", 1) for tok in perfs[0][1].split())
    cores = [int(x) for x in kv["core_instrs"].split(":")]
    bal = min(cores) / max(cores) if max(cores) else 0.0
    if bal < 0.99:                   return None, f"balance {bal:.3f}"
    kv["balance"] = f"{bal:.4f}"
    return kv, None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True, choices=["aes_gcm", "chacha_poly"])
    ap.add_argument("--impls", required=True, help="comma list of -i values")
    ap.add_argument("--blocks", required=True, help="comma list of -b values")
    ap.add_argument("--msgs", type=int, default=128)
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--warmup", type=int, default=5)
    ap.add_argument("--bitstream", required=True, help="label, e.g. combined")
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=int, default=180,
                    help="per-run seconds; exceeding it means the DMA wedged "
                         "and aborts the whole sweep")
    a = ap.parse_args()

    appdir = os.path.join(ROOT, "build32", "tests", "crypto", a.app)
    binary = os.path.join(appdir, a.app)
    if not os.path.exists(binary):
        sys.exit(f"missing {binary} -- build it for this bitstream first")
    env = dict(os.environ, VORTEX_DRIVER="de10pro",
               LD_LIBRARY_PATH=os.path.join(ROOT, "build32", "sw", "runtime"))
    bin_mtime = os.path.getmtime(binary)   # a concurrent `make` rebuilds this
    logdir = a.out + ".logs"; os.makedirs(logdir, exist_ok=True)
    stamp = git_stamp(); when = datetime.datetime.now().isoformat(timespec="seconds")
    new = not os.path.exists(a.out)
    cols = ["app", "impl", "bitstream", "msgs", "blocks_per_msg", "bytes", "runs", "warmup",
            "cycles_med", "cycles_q1", "cycles_q3", "cycles_min", "cycles_max",
            "instrs", "core_instrs", "balance", "cycles_per_byte_med", "git", "date"]
    with open(a.out, "a", newline="") as f:
        w = csv.writer(f)
        if new: w.writerow(cols)
        for impl in a.impls.split(","):
            for b in a.blocks.split(","):
                opts = ["-n", str(a.msgs), "-b", b, "-i", impl]
                tag = f"{a.app}_i{impl}_b{b}"
                if os.path.getmtime(binary) != bin_mtime:
                    sys.exit(f"ABORT: {binary} was rebuilt during the sweep "
                             f"(a concurrent make?) -- results would be inconsistent")
                with open(os.path.join(logdir, tag + ".log"), "w") as log:
                    cyc, kv0, bad, hang = [], None, None, False
                    for r in range(a.warmup + a.runs):
                        kv, err = run_once(binary, appdir, opts, env, log, a.timeout)
                        if kv == "HANG":
                            hang = True; bad = f"run {r}: {err}"; break
                        if err:
                            bad = f"run {r}: {err}"; break
                        if r < a.warmup: continue
                        if kv0 is None: kv0 = kv
                        elif kv["instrs"] != kv0["instrs"]:
                            bad = f"instrs drift {kv0['instrs']} -> {kv['instrs']}"; break
                        cyc.append(int(kv["cycles"]))
                if hang:
                    reset = os.path.join(ROOT, "build32", "sw", "runtime",
                                         "vortex-de10pro-reset")
                    if os.path.exists(reset):
                        subprocess.run([reset], env=env)   # MMIO CP reset, no DMA
                    sys.exit(f"ABORT: {tag} hung ({bad}); the DMA is likely "
                             f"wedged. Stopping before a mid-DMA kill makes it "
                             f"worse -- reboot if the next run also hangs.")
                if bad or len(cyc) < a.runs:
                    print(f"  {tag}: REJECTED ({bad or 'short'})", flush=True); continue
                cyc.sort(); q = statistics.quantiles(cyc, n=4)
                med = statistics.median(cyc); byt = int(kv0["bytes"])
                w.writerow([a.app, kv0["impl"], a.bitstream, a.msgs, b, byt, a.runs, a.warmup,
                            int(med), int(q[0]), int(q[2]), cyc[0], cyc[-1],
                            kv0["instrs"], kv0["core_instrs"], kv0["balance"],
                            f"{med/byt:.4f}", stamp, when]); f.flush()
                print(f"  {tag}: {kv0['impl']:>9} bytes={byt:>7} cycles med={int(med):>9} "
                      f"IQR=[{int(q[0])},{int(q[2])}] c/B={med/byt:.4f} instrs={kv0['instrs']}", flush=True)
    print("SWEEP DONE")

if __name__ == "__main__":
    main()
