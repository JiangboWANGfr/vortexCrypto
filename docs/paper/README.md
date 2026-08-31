# HARE -- DAC draft

`main.tex` + `hare.bib`; the data tables and the width figure under
`tables/` are **generated** -- edit `gen_tables.py`, not the `.tex` files:

    python3 gen_tables.py     # reads ../proposals/data/measure-n128-2r1w-v2.csv
                              # (+ its .yaml sidecar) and $RESULTS
    latexmk -pdf main.tex

Every number in the tables traces to one of two sources: the frozen, gated
measurement dataset, or an archived Quartus `fit.summary`/`sta.summary`
under `fpga_proj/PCIE_DDR4_Vortex_G3X16/results/`. The generator enforces:
schema v2, shape c2w4t16, n=128, per-core balance >= 0.90 in every row, a
declared git stamp, a matching config hash, same-build S1 anchors for the
S3/16 rows, and the three-point fit consistency gates below.

Decisions of record:

- Performance numbers come ONLY from dataset `measure-n128-2r1w-v2`
  (77 rows; tag `hare-dac-measure-n128-v1` marks the freeze). The
  historical `crypto_measurements.csv` (n=64, one active core on the lane
  side) is superseded for lane-vs-subgroup ratios; the correction history:
  4.98x -> 4.08x (two-point, matched utilisation) -> 4.32x (three-point,
  matched 128-512 KiB byte range).
- Regimes are named small-/large-footprint, not cache-resident/memory-
  bound, until counter runs prove the mechanism. Mainline tiers (S1, S2,
  each algorithm's subgroup form) fit THREE points per regime with an
  intercept: small 4-32 KiB, large 128-512 KiB for BOTH algorithms --
  the AES large fit sits at b=64,128,256 because its old 64-128 KiB span
  was still inside the footprint transition (marginal +24%/doubling).
  Every fit point is a power-of-two blocks count: the retained b=24/48
  diagnostic rows show non-power-of-two strides land 7-25% off the line
  for lane/engine tiers (~1% for subgroup tiers). Gates: 3-point vs
  2-point slope <= 5%, middle point <= 5% off the endpoint chord.
- Exception of record: the S3/16 small fit keeps its endpoint pair
  (chord 0.881 c/B; the 3-point LSQ gives 0.802, a 9% estimator spread
  because sg16's 8.6k-cycle per-message start-up makes payload ~2% of a
  small run). The chord is the conservative choice.
- S0 and SG4 rows keep two-point pairs on their original ranges (both are
  flat, so cross-range ratios move a few percent at most).
- Marginal figures are only half the story and the paper now says so:
  per-message start-up is ~0.8k cycles (S2), ~1.2k (S1), ~8.6k (SG16).
  Whole-run, SG16 overtakes S1 near 1.3 KiB records but overtakes S2 only
  near 100 KiB; at 2 KiB records S2 is 2.9x faster whole-run. The S2-vs-
  SG16 statement of record: SG16 has the lowest MARGINAL cost in both
  regimes (tied large-footprint, 1.61x small), carries no persistent
  context, and pays for that statelessness in start-up -- never "SG16
  beats S2 outright".
- The width story is width-AND-granularity matching; the ARX16 ablation
  (1.78x slower at fixed width) isolates the granularity half.
- All ratios are computed by the generator from unrounded slopes; tables
  display three decimals. Do not hand-derive ratios from displayed values.
- No absolute Gb/s in abstract/intro/tables; cycles-per-byte and relative
  speedups only. One absolute anchor sentence in Sec. VI-A per-core, plus
  whole-run MB/s at fixed record lengths where start-up is discussed.
- dALM is measured against the crypto-free build (183,971 ALMs), not the
  tree's "base" build -- base already contains the AES lane-local units.
- The sg16 area figure is the 2R1W build (223,427); the R4 predecessor
  (223,209) is preserved as results/c2w4t16.sg16-r4.
- The GPU-TEE overhead numbers (12.69x etc.) are deliberately NOT cited in
  the intro; the two arXiv papers appear once in related work, no numbers.
- bib entries marked TODO-verify need checking before submission.

Open items: the draft is 7 pages against DAC's 6 -- needs a compression
pass; same-version PPA
(U5); correctness/boundary audit + gate self-test (U6); board (U7).
