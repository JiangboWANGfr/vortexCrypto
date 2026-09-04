# AES S1->S3 marginal: silicon vs two rtlsim memory models (2026-09-04)

All AES-GCM, n=128, large-footprint (b=64,128,256) and small (b=2,4,8)
three-point marginal fits, cycles/byte. Same kernel binary, same combined
bitstream / RTL revision; only the memory model differs.

  dataset                       S1 lg   S3 lg  S1/S3 lg    S1 sm  S3 sm  S1/S3 sm
  board (silicon)               2.820   1.041     2.71     2.677  0.937      2.86
  board-matched rtlsim, 1 bank 11.827   1.295     9.13     6.527  0.927      7.04
  frozen rtlsim, 2-bank (paper) 4.853   0.987     4.92     3.811  0.656      5.81

Sources: board = board-u7-20260904.csv (gated, 5 warm-up + median of 30);
board-matched = rtlsim-boardmatched-aes-20260904.csv (DE10-Pro platform
config: 1 DDR bank, no interleave, 3-cycle caches, F/D disabled, 200 MHz);
frozen = measure-n128-2r1w-v2.csv (the paper's dataset, 2-bank interleaved,
2-cycle caches). Instruction counts are bit-identical across all three, so
the differences are purely cycles from the memory model.

Ramulator over-penalizes SCATTERED access far more than COALESCED. Cycle
ratio rtlsim(1-bank)/silicon:
  hw_s1 (scattered, 79 DRAM B/B): 3.44x (b8), 2.51x (b64), 3.69x (b256)
  hw_s3g (coalesced,  9 DRAM B/B): 2.99x (b8), 1.48x (b64), 1.29x (b256)
So the S1 anchor is inflated in rtlsim, inflating the S1->S3 ratio: 9.13x
(1-bank rtlsim) and 4.92x (2-bank rtlsim) collapse to 2.71x on silicon.

IMPLICATION (decision for the author): the paper's AES S3/4 headline of
4.92x/5.81x is a ramulator artifact. On silicon the deployable figure is
2.71x/2.86x. The methodology already names the board as source of record.
The ChaCha SG16 headline (4.32x rtlsim) is NOT yet measured on silicon --
the sg16 board sweep must be re-run (it was corrupted by a concurrent
build and an intermittent hang). It may drop similarly.

## ChaCha added (2026-09-04, sg16 sweep completed with reset-and-retry)

Board ChaCha-Poly, same-CSV S1 anchor, 3-point marginal:
  S1   large 2.539 c/B  small 2.523 c/B
  SG16 large 1.532 c/B  small 1.403 c/B   (intercept ~486k cycles: the 8.6k
                                            cyc/record start-up, 128 records)
  -> board S1->SG16 = 1.66x large, 1.80x small

FULL BOARD-vs-PAPER (marginal speedup over same-build S1):
  pair              board(silicon)   paper(rtlsim, published)
  AES  S1->S3/4     2.71x / 2.86x    4.92x / 5.81x
  ChaCha S1->SG16   1.66x / 1.80x    4.32x / 8.41x

Both collapse on silicon, and for the same reason: ramulator over-penalizes
the scattered lane-mapped S1 access (established for AES: 2.5-3.7x slower
than silicon on hw_s1) far more than the coalesced subgroup access, which
inflates the S1 anchor and thus the S1->subgroup ratio. On real DDR4 the S1
baseline is much faster, so the subgroup win is smaller. Whole-run, at 512
KiB records sg16 is only 1.04x faster than S1 in total cycles (1,289,343 vs
1,346,350) because of its ~486k-cycle start-up.

Instruction counts are bit-identical board vs rtlsim, so this is purely a
DRAM-timing difference, not a functional one. The board numbers passed the
gate (5 warm-up + median of 30/10-12, IQR <1.5%, dev-from-chord <1.5%).

DECISION FOR THE AUTHOR: the paper's central speedups are ~1.8x (AES) to
~2.6x (ChaCha) smaller on silicon than the rtlsim headline. Options:
(1) re-baseline every headline to the board (honest, methodology already
    names board as source of record; the story survives qualitatively --
    subgroup still lowest marginal, S1 still barely helps ChaCha -- but the
    numbers drop a lot);
(2) keep rtlsim numbers but frame them as a 2-channel-memory machine and
    disclose the board deltas + the ramulator-scattered-access caveat.
Not decided here; no paper edit made.

## ChaCha SG4 added (2026-09-04, s3f bitstream, program+reboot)

Board ChaCha, same-CSV S1 anchor, large-footprint marginal:
  S1   2.539 c/B  i/B 1.180   1.00x
  SG4  2.651 c/B  i/B 1.414   0.96x  (4 lanes: SLOWER than S1, MORE instrs --
                                      cannot span the 512-bit state)
  SG16 1.532 c/B  i/B 0.766   1.66x  (16 lanes: the win)

WIDTH RULE on silicon is sharper than in rtlsim. rtlsim: SG4 1.29x -> SG16
4.32x (narrow still helps). Silicon: SG4 0.96x -> SG16 1.66x (narrow gives
NOTHING, and costs more instructions). The qualitative claim "the subgroup
must span the block state" is intact and cleaner on the board; only the
magnitudes shrink.

Board rows still needing their own bitstream (one reboot each): AES S2
(hw_s2, s2p), ChaCha S2 (s2, chacha-s2p), arx16 stateless ablation.

## ChaCha S2 added (2026-09-04) -- OVERTURNS the marginal-cost claim

Board ChaCha, large-footprint marginal (c/B), same-CSV S1 anchor:
  S1   2.539  i/B 1.180  1.00x  intercept 13k
  S2   0.719  i/B 0.451  3.53x  intercept 16k   <- engine, fastest on BOTH axes
  SG4  2.651  i/B 1.414  0.96x  intercept 108k
  SG16 1.532  i/B 0.766  1.66x  intercept 486k

THE PAPER'S CENTRAL CLAIM DOES NOT HOLD ON SILICON. Paper (rtlsim): SG16 has
the lowest marginal, "essentially tied" with S2 (1.728 vs 1.807 c/B), and
crosses over S2 near 100 KiB. Board: S2's marginal (0.719) is HALF SG16's
(1.532), and S2's intercept (16k) is 30x below SG16's (486k). S2 dominates
SG16 on both slope and intercept -- there is no crossover; SG16 never catches
S2 on performance. Cause: S2's instruction stream is the shortest (i/B 0.451),
and on real DDR4 (vs ramulator) instruction count, not scattered-DRAM
penalty, decides -- exactly the effect that inflated the S1 anchor also
un-inflates S2 relative to the subgroup.

Consequence for the argument: "subgroup instructions carry the lowest
marginal cost for both AEADs" is false on silicon for ChaCha. SG16's case is
no longer speed; it is (a) area -- SG16 pair +2.8% vs the ChaCha S2 engine's
much larger bundle -- and (b) no persistent per-(warp,lane) key context. The
framing must move from "S3 is the sweet spot / fastest" to "S3 buys
near-engine throughput without a persistent secret namespace and at a
fraction of the area." Still to measure (one reboot each): AES S2 (likely the
same inversion), arx16 ablation.

## AES S2 added (2026-09-04) -- the result is a SPLIT, not a refutation

Board large-footprint marginal (c/B), same-CSV S1 anchor, both algorithms:
                S1      S2            S3(subgroup)   lowest marginal
  AES    large  2.820   1.115(2.53x)  1.041(2.71x)   S3 (SG4, 4 lanes)
  ChaCha large  2.539   0.719(3.53x)  1.532(1.66x)   S2 (engine)
  AES    small  2.677   0.402(6.66x)  0.937(2.86x)   S2
  ChaCha small  2.523   0.591(4.27x)  1.403(1.80x)   S2

Correction to the ChaCha-only note above: with AES S2 in hand, the paper's
"subgroup lowest marginal for BOTH" is HALF right on silicon -- true for AES,
false for ChaCha -- and the split is mechanistic, not noise. AES state is 128
bits -> 4-lane subgroup -> 32 records in flight -> small start-up (intercept
~9k) -> the subgroup wins the marginal. ChaCha state is 512 bits -> 16-lane
subgroup -> 8 records in flight -> huge start-up (intercept ~486k) -> the
engine wins. The board thus SHARPENS the paper's own width/start-up rule: the
subgroup wins when the block state is small enough that its subgroup stays
narrow; when the state forces a wide subgroup, start-up dominates and the
stateful engine is faster. Small-footprint, S2 wins both (context amortizes
start-up), exactly as the paper says.

Framing that survives (option C): the paper is a design-space map, not a
"we win" claim. S2 is fastest but costs ~3x area and a persistent per-(warp,
lane) key context; S3 wins AES and trades ChaCha speed for a third of the
area and no resident secret. All measured on silicon.
Remaining: arx16 ablation (granularity axis), one reboot.

## arx16 ablation added (2026-09-04) -- granularity axis confirmed, sharper

At the SAME 16-lane width (impl label sg16 for both; distinguished by
bitstream): dr.sg16 large marginal 1.532 c/B vs arx.sg16 3.302 c/B -> the
double-round macro is 2.16x faster than the stateless per-line form (paper
rtlsim: 1.78x). arx.sg16 is even slower than S1 (0.77x). So the subgroup's
win is about GRANULARITY (a whole double-round per instruction), not only
width -- the paper's width-and-granularity co-design rule, confirmed on
silicon and sharper than in simulation.

## MASTER board table (all 8 configs, large-footprint marginal, x S1)
              AES              ChaCha
  S1      2.820  1.00x     2.539  1.00x
  S2      1.115  2.53x     0.719  3.53x   (engine)
  SG4     1.041  2.71x     2.651  0.96x   (AES: the win / ChaCha: useless)
  SG16      --             1.532  1.66x   (dr)
  arx.sg16  --             3.302  0.77x   (stateless per-line ablation)

Silicon story, coherent across all three axes:
  WIDTH:      ChaCha SG4 0.96x -> SG16 1.66x (must span the 512-bit state)
  GRANULARITY: at 16 lanes, dr 1.532 vs arx 3.302 = 2.16x (macro, not line)
  STATE:      S2 fastest for ChaCha (wide state, 486k start-up sinks SG16);
              S3 fastest for AES (narrow 4-lane, tiny start-up). Split is
              mechanistic and tracks start-up. Small records: S2 wins both.
The width-and-granularity RULE (contribution 2) is validated and sharper.
The "S3 lowest marginal for both" phrasing (in contribution 3 / the eval) is
half-true and must become the honest design-space map: S3 wins AES, and buys
ChaCha near-competitive throughput without a persistent secret and at ~1/3
the area. No S0 board rows (FPU-less core hangs the software kernels);
counters stay rtlsim (board cannot expose them).

## S0 baselines added (2026-09-04) -- S0 runs on silicon, sw-vs-rori resolved

S0 is NOT blocked on the FPU-less board (earlier "hang" was a stale rtlsim
build + a wedged board, misread). AES sw_ttable and ChaCha sw/rori all run
on the board (pure software, any bitstream). S0->S1 marginal, silicon:
  AES:    S1 2.820  vs  S0(sw_ttable) 34.234  ->  12.1x  (rtlsim 14.6-18.2x)
  ChaCha: S1 2.539  vs  S0(sw) 4.374 / rori 4.448 -> 1.72x/1.75x (rtlsim 1.55x)
The "S1 helps AES ~12x, barely helps ChaCha ~1.7x" contrast holds on silicon.

sw vs rori on silicon: within 2% (sw 4.374 vs rori 4.448 large marginal; rori
faster at b=1). The rtlsim "sw 12.5% faster" was itself a ramulator artifact.
So rori is a fine S0 row (the paper's choice stands); the ladder does not
hinge on it. chacha-s0-rori-20260903.md's conclusion is superseded by this.

## COMPLETE board map (both algorithms, all tiers, large-footprint x S1)
              AES                 ChaCha
  S0     0.08x (sw_ttable)   0.58x (sw) / 0.57x (rori)
  S1     1.00x               1.00x
  S2     2.53x               3.53x
  SG4    2.71x               0.96x
  SG16     --                1.66x
  arx16    --                0.77x
Only the mechanism counters (DRAM B/B, stalls, IPC) remain rtlsim-only --
the board cannot expose them; they stay disclosed as simulated.
