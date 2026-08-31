#!/usr/bin/env python3
"""Prove the bench.py recording gate, end to end.

    test_bench_gate.py          # unit tests only, instant
    test_bench_gate.py --sims   # + three simulator runs (needs build32, simx)

The gate exists so that a run whose answer is wrong can never become a row:
the applications print their PERF line before they verify, so an ungated
line can belong to a wrong answer. Unit tests cover every verdict path and
the records.csv header guard; --sims proves the wiring with real runs:

  1. chacha_poly -i11 (its tag is wrong BY DESIGN) without --expect-fail
     must be refused, and records.csv must not grow;
  2. the same run with --expect-fail must be recorded;
  3. aes_gcm -i8 with a tail must be refused as SKIPPED (whole blocks only),
     and nothing recorded -- the boundary the SG4 hot path does not support
     is rejected, not miscomputed.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bench  # noqa: E402

FAILS = 0

def check(cond, what):
    global FAILS
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        FAILS += 1

REC = [{"impl": "x"}]

def unit():
    v = bench.run_verdict
    check(v(0, "stuff\nPASSED!\n", REC, False) is None, "clean run records")
    check(v(1, "stuff\nPASSED!\n", REC, False) == "exit 1",
          "nonzero exit refused even with PASSED")
    check(v(0, "stuff\nFAILED!\n", REC, False) == "no PASSED! line",
          "wrong answer (FAILED) refused")
    check(v(0, "stuff\n", REC, False) == "no PASSED! line",
          "silent exit refused")
    check(v(0, "x", REC * 2, False) is not None, "two PERF lines refused")
    check(v(2, "stuff\nFAILED!\n", REC, True) is None,
          "--expect-fail records the deliberate failure")
    check(v(0, "stuff\nPASSED!\n", REC, True) is not None,
          "--expect-fail refuses a run that did not fail")

    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "records.csv")
        with open(p, "w") as fh:
            fh.write("app,impl,old_schema\n1,2,3\n")
        try:
            bench.append_records(p, [])
            check(False, "old-schema records.csv refused")
        except SystemExit:
            check(True, "old-schema records.csv refused")

def sims():
    chacha_cfg = ("-DVX_CFG_EXT_AUTH_ENABLE -DVX_CFG_EXT_AUTH_POLY_ENABLE "
                  "-DVX_CFG_EXT_AUTH_POLY_SG4_ENABLE "
                  "-DVX_CFG_EXT_SYM_CHACHA_ENABLE "
                  "-DVX_CFG_EXT_SYM_CHACHA_SG4_ENABLE -DVX_CFG_EXT_SYM_ENABLE")
    aes_cfg = ("-DVX_CFG_EXT_SYM_ENABLE -DVX_CFG_EXT_AUTH_ENABLE "
               "-DVX_CFG_EXT_SYM_SG4_ENABLE -DVX_CFG_EXT_AUTH_SG4_ENABLE")

    def run(app, opts, cfg, runs, expect_fail=False):
        argv = [sys.executable, os.path.join(HERE, "bench.py"), "--driver",
                "simx", "--app", app, "--runs", runs, "--configs", cfg] + opts
        if expect_fail:
            argv.append("--expect-fail")
        r = subprocess.run(argv, capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr

    def rows(runs):
        p = os.path.join(runs, "records.csv")
        return sum(1 for _ in open(p)) - 1 if os.path.exists(p) else 0

    with tempfile.TemporaryDirectory() as td:
        rc, out = run("chacha_poly", ["-n", "8", "-b", "1", "-i", "11"],
                      chacha_cfg, td)
        check(rc != 0 and "NO RECORD" in out and rows(td) == 0,
              "wrong-tag run (chacha -i11) refused, csv untouched")
        rc, out = run("chacha_poly", ["-n", "8", "-b", "1", "-i", "11"],
                      chacha_cfg, td, expect_fail=True)
        check(rc == 0 and rows(td) == 1,
              "same run with --expect-fail recorded")
        rc, out = run("aes_gcm", ["-n", "8", "-b", "2", "-t", "5", "-i", "8"],
                      aes_cfg, td)
        check(rc != 0 and "SKIPPED" in out and rows(td) == 1,
              "unsupported tail (aes sg4) refused as SKIPPED, csv untouched")

if __name__ == "__main__":
    unit()
    if "--sims" in sys.argv:
        sims()
    print("---", "FAILED" if FAILS else "all checks passed")
    sys.exit(1 if FAILS else 0)
