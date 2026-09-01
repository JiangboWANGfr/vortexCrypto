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
- Asymmetry of record: there is NO Poly1305 S2 engine -- the ChaCha S2 row
  is cipher engine + lane-local poly26.mac (AES S2 is a dual engine).
  Counters put 42% of the S2 row's instructions in the authenticator, so
  the S2-vs-SG16 marginal tie is against a partially-engined S2; the paper
  discloses this in IV-B and V-A. Rationale: Poly's 5-limb state fits ten
  GPRs and its block step is ten R4 MACs (no GHASH-class engine win), and
  a poly engine would add a second per-(warp,lane) context class.
- All ratios are computed by the generator from unrounded slopes; tables
  display three decimals. Do not hand-derive ratios from displayed values.
- No absolute Gb/s in abstract/intro/tables; cycles-per-byte and relative
  speedups only. One absolute anchor sentence in Sec. VI-A per-core, plus
  whole-run MB/s at fixed record lengths where start-up is discussed.
- dALM is measured against the crypto-free build (183,971 ALMs), not the
  tree's "base" build -- base already contains the AES lane-local units.
- U5 same-version PPA (2026-09-01, data/fits-2026-09-01/): all ten fits at
  one clean commit (af28f), one constraint set, Quartus 19.2, seed 6. The
  seven stale fits were replaced -- AES S2 shrank 10.8k ALMs (its old fit
  predated the context slimming), ChaCha S2 grew 7.6k (QR pipelining), so
  ChaCha S2 is now the most expensive point (+112,951) and the S2/SG16
  area ratio is 2.86x. SG16-over-ChaCha-S1 is +7,388 (3.4%, was 2.8%).
  Combined HARE, fitted for the first time: +94,524 (51.4%), cheaper than
  the ChaCha engines alone. The arx16-below-sg16 gap narrowed to 1,386
  ALMs on same-version fits (5,573 had mixed revisions).
- Combined's one hold corner misses by 2 ps at seed 6 (setup all
  non-negative everywhere); a seed-7 re-fit is pending, both seeds to be
  reported. Single-seed (6) throughout otherwise; a 3-seed pass is a
  pre-submission nice-to-have.
- The S2 register-predictability sentence dropped its "within 2.4%" figure
  pending re-derivation from the new fits' entity tables.
- The sg16 area figure is the 2R1W build (223,427); the R4 predecessor
  (223,209) is preserved as results/c2w4t16.sg16-r4.
- The GPU-TEE overhead numbers (12.69x etc.) are deliberately NOT cited in
  the intro; the two arXiv papers appear once in related work, no numbers.
- Bibliography verified 2026-08-31; no TODO-verify entries remain.
- The sg16 tail-stride bug (fixed in 7143196b5; found by the first sg16
  tail case ever written) affects no t=0 measurement. Re-anchored at the
  fix commit the sg16 ratios read 9.24x/4.45x vs the published 8.41x/4.32x
  -- v2 is the conservative pair and stands. Policy: datasets re-baseline
  at milestones (the pre-submission freeze), not per commit.

- Combined-build cross-check (U4, data/measure-n128-combined-v1.csv):
  anchors and subgroup forms re-measured in the deployable Combined build
  reproduce v2 to <= 1.5% (three of four bit-identical). Headlines stay
  sourced from v2; the PPA's Combined configuration is
  SYM+AUTH + SYM_SG4/AUTH_SG4 + SYM_CHACHA/AUTH_POLY +
  SYM_CHACHA_SG16/AUTH_POLY_STEP16.

Open items: the draft is 7 pages against DAC's 6 -- needs a compression
pass; combined seed-7 re-fit; re-derive the S2 register-predictability
figure; board (U7); final re-baseline of the performance dataset at the
submission commit.
