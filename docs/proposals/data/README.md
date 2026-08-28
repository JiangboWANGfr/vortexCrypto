# Measurement records for the crypto ISA proposal

`crypto_measurements.csv` is every simulator run behind the numbers in sections
17 through 23 of `../crypto_isa_proposal.md`, one row per run, self-describing.

It exists because the raw run logs were not going to survive: they were written
to a session temporary directory, and the document's tables were the only
durable record of them. Two arithmetic errors were caught by re-deriving figures
from those logs while they still existed, which is not a process that works once
they are gone.

Those logs have since been moved out of `/tmp`. All 649 files, 78 MB, are now in
`build32/crypto_runs/archive-2026-08/`, verified identical by checksum. The `log`
column is a path relative to `build32/crypto_runs/`, one base for every row: the
original ones sit under `archive-2026-08/`, later batches under their own
directory. All 444 rows resolve to a file that exists.

## Columns

| column | meaning |
| --- | --- |
| `app` | `aes_gcm` or `chacha_poly` |
| `impl` | the `-i` row, as the application prints it |
| `driver` | `simx` or `rtlsim`; rtlsim is authoritative for cycles |
| `cores`, `warps`, `threads` | the shape, taken from the application's own banner rather than from the build flags |
| `msgs`, `blocks_per_msg`, `blocks`, `bytes` | the problem size |
| `cycles`, `instrs` | what the run retired |
| `opts` | the command line |
| `extensions` | which `VX_CFG_EXT_*` macros the build carried |
| `log` | path under `build32/crypto_runs/` to the run it came from |

`impl` is what the application prints, not what the hardware is. Two different
instructions report `sg16`: `chacha.dr.sg16` and `chacha.arx.sg16` are the same
`-i12` row of the same kernel, selected by which macro the build carried, so
they are told apart only by `SYM_CHACHA_SG16` against `SYM_CHACHA_ARX16` in
`extensions`. Filtering on `impl` alone mixes two designs that differ by 2.19x.

A block is **16 bytes** for `aes_gcm` and **64 bytes** for `chacha_poly`. Any
comparison across the two must go through `bytes`, not `blocks`; the `cycles/B`
table in section 23.5 exists because an earlier draft did not.

## Reading a marginal figure

Every per-block figure in the document is a two-point marginal fit, never a
total divided by a count -- the latter carries the per-message setup, which at
small `blocks_per_msg` dominates:

```
per_block = (metric[hi] - metric[lo]) / (blocks[hi] - blocks[lo])
```

with `lo`/`hi` = 1/4 (cache-resident, 4-16 KB working set) and 16/32
(memory-bound, 64-128 KB) for `chacha_poly`, and 8/64 for `aes_gcm`. Rows for a
fit must share `driver`, `warps` and `extensions` -- **and must come from the
same batch**, because `extensions` does not identify a build. rtlsim is
deterministic for a given binary: four repeats of each `sg16` size in the
`paper16` batch are byte-identical in cycles and instructions, so there is no
run-to-run noise anywhere in this file and every difference between two rows is
a difference in the design, the kernel or the configuration. Those differences
are not small. `chacha_poly` `s1` at b16, same `extensions` and same shape,
reads 513,086 in the `measure` batch and 500,015 in `paper16` -- 2.5% on the
total and 6.4% at b1. Mixing batches inside one fit is the easiest way to
manufacture a result.

## Where the runs live

| | |
| --- | --- |
| `crypto_measurements.csv` | 444 rows, in the repository, the durable record |
| `build32/crypto_runs/archive-2026-08/` | the logs the first 271 rows came from |
| `build32/crypto_runs/<batch>/logs/` | logs from later batches, one file per run |
| `build32/crypto_runs/<batch>/records.csv` | that batch's rows, same 15 columns |

Give each batch its own `--runs` directory. A CI-configuration sweep and a
measurement sweep must not share a `records.csv`: they are the two things whose
mixture is the 43% error above. The CI sweep run here is in
`records-ci-config.csv` and is deliberately **not** merged into this file.

`build32/` is gitignored, so the logs are on disk but not in version control and
not backed up. `rm -rf build32` destroys them; the CSV in the repository is what
is meant to survive that. Set `RUNS=<dir>` to put them somewhere else.

## Reproducing

Run `tests/crypto/bench.py` from anywhere -- it resolves the source tree from
its own location, so no `cd` is needed and it never reads the build tree's copy
of the case catalog (which `configure` snapshots once and lets go stale).

It builds the app itself, but it does not create the build tree. `build32/` in
this repository is already configured; a fresh one is the standard Vortex setup:

```sh
mkdir -p build32 && cd build32 && ../configure --xlen=32
```

If a test directory goes missing, `../configure --xlen=32` re-copies it -- it is
idempotent, and the app inside gets built on the next run. **Do not reach for
`make -C build32`**: that is a whole-tree build and stops in `third_party` on
dependencies (`cocogfx` wants libpng) that no crypto test touches. Point at a
different tree with `--build <dir>`; given a directory that is not a build tree
at all, the script says so and prints the configure line.

One invocation runs one case, keeps the whole log, and appends the parsed
record. `--list` shows what is available:

```sh
tests/crypto/bench.py --list
for b in 16 32; do tests/crypto/bench.py --case crypto-chacha-poly-s2 -b $b; done
```

A case name comes from `ci/testcases/crypto.yaml`, the only place that records
which extension macros each implementation needs -- getting that set wrong is
silent, since the kernel still runs, just a different one. The shape is not in
the catalog (CI does not care about it), so `--shape` defaults to the recorded
`c2w4t16`, and block counts are overridden per run because a marginal fit needs
two points and a catalog case has one.

**A catalog case is not the configuration a recorded row was measured in.**
`crypto-chacha-poly-s2` enables only the S2 engine, to isolate it; the measured
S2 row had `SYM_CHACHA` on as well and ran `-t37 -a20` shorter. Fitted side by
side: **1.08 c/B vs 1.90 c/B — a 43% spread from configuration alone**, against
a 4% noise floor. To reproduce a row, drive it from that row's own `extensions`
and `opts` columns:

```sh
tests/crypto/bench.py --app chacha_poly -n 64 -b 16 -i 10 \
  --configs "-DVX_CFG_EXT_SYM_ENABLE -DVX_CFG_EXT_AUTH_ENABLE \
             -DVX_CFG_EXT_AUTH_POLY_ENABLE -DVX_CFG_EXT_SYM_CHACHA_ENABLE \
             -DVX_CFG_EXT_SYM_CHACHA_S2_ENABLE"
```

Done that way the recorded ChaCha-Poly S2 figure reproduces at **1.911 c/B
against the archived 1.898 c/B, +0.7%**.

The `extensions` column is read back out of
`build32/tests/crypto/<app>/config.stamp` -- what the build actually compiled,
not what was typed. A run that yields no `<APP>_PERF:` line prints `NO RECORD`
and exits non-zero rather than appending nothing quietly.

Per-class counters -- stalls, instruction mix, load latency, load and store
counts -- need `PERF=1` on the make and `VORTEX_PROFILING=1` in the environment.
They go into the log but not the CSV; several of the document's conclusions rest
on them, and section 21.6 records why they settle questions that static counts
cannot.

The fitter results live outside this repository, in the FPGA project's
`results/` directory, one subdirectory per build.
