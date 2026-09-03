# Board vs rtlsim cross-check (2026-09-03)

Setup: DE10-Pro running the combined bitstream (constraint set b8147cf,
seed 6), PCIe Gen3 x16, 200 MHz Vortex clock. rtlsim rebuilt with the
IDENTICAL platform configs (F/D disabled, 3-cycle caches, one memory
bank, no interleave) and the identical kernel binary. AES hw_s3g
(aesrm/aesrf.sg4 + ghmul.sg4), n=128, both runs PASSED on both targets.

  point            instrs (board = rtlsim)   cycles board   cycles rtlsim
  b=8   (16 KiB)   16,002 (8001:8001) both        36,345         107,944
  b=64 (128 KiB)   96,642 (48321:48321) both     145,492         216,170

Findings:
1. Instruction counts, including the per-core split, are BIT-IDENTICAL
   between silicon and RTL simulation -- same binary, same path.
2. Silicon is faster (2.97x at 16 KiB, 1.49x at 128 KiB): ramulator's
   DRAM model is pessimistic, mostly in latency (the gap shrinks as the
   run becomes bandwidth-shaped). Simulated figures are conservative.
3. The marginal slope transfers: board (145,492-36,345)/114,688 = 0.952
   c/B against rtlsim (216,170-107,944)/114,688 = 0.944 c/B -- within
   0.9%. The model-vs-silicon difference lives almost entirely in the
   intercept; the paper's headline metric survives contact with hardware.

Note: the frozen dataset's rtlsim rows use different platform parameters
(2-bank interleaved memory, 2-cycle caches), so they are not directly
comparable to board runs; this cross-check holds every knob equal.
