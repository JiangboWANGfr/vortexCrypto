# Measurement records for the crypto ISA proposal

`crypto_measurements.csv` is every simulator run behind the numbers in sections
17 through 23 of `../crypto_isa_proposal.md`, one row per run, self-describing.

It exists because the raw run logs did not survive: they were written to a
session temporary directory -- 78 MB across 320 files -- and the document's
tables were the only durable record of them. Two arithmetic errors were caught
by re-deriving figures from those logs while they still existed, which is not a
process that works once they are gone.

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
| `log` | the scratch file it came from, for provenance |

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
fit must share `driver`, `warps` and `extensions`; the same row measured in two
different builds moves by up to 4% on cycles, which is instruction layout, not
noise in the measurement.

## Reproducing

```sh
cd build32
CONFIGS="-DVX_CFG_EXT_SYM_ENABLE -DVX_CFG_EXT_AUTH_ENABLE ..."   # the `extensions` column
make -C tests/crypto/<app> run-<driver> CONFIGS="$CONFIGS" OPTS="<opts>"
```

Per-class counters -- stalls, instruction mix, load latency, load and store
counts -- need `PERF=1` on the make and `VORTEX_PROFILING=1` in the environment.
They are not in this file; several of the document's conclusions rest on them,
and section 21.6 records why they settle questions that static counts cannot.

The fitter results live outside this repository, in the FPGA project's
`results/` directory, one subdirectory per build.
