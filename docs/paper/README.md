# HARE -- DAC draft

`main.tex` + `hare.bib`; the data tables and the width figure under
`tables/` are **generated** -- edit `gen_tables.py`, not the `.tex` files:

    python3 gen_tables.py     # reads ../proposals/data/measure-n128-2r1w-v1.csv
                              # (+ its .yaml sidecar) and $RESULTS
    latexmk -pdf main.tex

Every number in the tables traces to one of two sources: the frozen,
gated measurement dataset, or an archived Quartus
`fit.summary`/`sta.summary` under
`fpga_proj/PCIE_DDR4_Vortex_G3X16/results/`. The generator autofills area
from the reports when present and falls back to the values read on
2026-08-29 (printed to stderr when it does). The dataset loader enforces:
schema v2, shape c2w4t16, n=128, per-core instruction balance >= 0.90 in
every row, a git stamp the sidecar declares, a matching config hash, and a
same-build S1 anchor for the S3/16 rows.

Decisions of record:

- Performance numbers come ONLY from dataset `measure-n128-2r1w-v1`
  (48 rows, tag `hare-dac-measure-n128-v1`). The historical
  `crypto_measurements.csv` (n=64) is superseded for lane-vs-subgroup
  ratios: at n=64 lane-mapped kernels idle core 1, so the old ChaCha
  headline 4.98x corrects to 4.08x memory-bound (an 18.1% reduction;
  equivalently, the old figure was 22.1% above the corrected one) and
  8.41x cache-resident, both against the same-build S1 anchor.
- Both regimes are reported (cache-resident b=1..4 / 8 KiB..32 KiB and
  memory-bound b=16..32 / 128 KiB..256 KiB pairs at n=128); the abstract
  headlines the conservative memory-bound side. Each regime is a two-point
  fit, so prose calls these balanced preliminary RTL results; before
  submission add third/fourth points per regime (cache b={1,2,4,8},
  memory b={16,24,32,48}) and refit.
- All ratios are computed by the generator from unrounded slopes; tables
  display three decimals. Do not hand-derive ratios from displayed values.
- The S2-vs-SG16 statement of record: SG16 has the lowest observed cost in
  both regimes -- essentially tied with S2 memory-bound (1.756 vs 1.835
  c/B), 1.60x ahead cache-resident -- never "SG16 beats S2 outright".
- The width story is stated as width-AND-granularity matching: the SG16
  form also raises per-instruction granularity, and the ARX16 ablation
  (1.75x slower at fixed width) isolates the granularity half.
- No absolute Gb/s in abstract/intro/tables; cycles-per-byte and
  relative speedups only. One absolute anchor sentence in Sec. VI-A with
  the per-core figure.
- dALM is measured against the crypto-free build (183,971 ALMs), not the
  tree's "base" build -- base already contains the AES lane-local units.
- The sg16 area figure is the 2R1W build (223,427); the R4 predecessor
  (223,209) is preserved as results/c2w4t16.sg16-r4.
- The GPU-TEE overhead numbers (12.69x etc.) are deliberately NOT cited in
  the intro; the two arXiv papers appear once in related work, no numbers.
- bib entries marked TODO-verify need checking before submission.
