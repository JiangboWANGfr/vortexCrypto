# GHASH multiplier stages in the Combined build (2026-09-03)

Companion to ghash-area-2026-09-03.csv. All three fits are the Combined
configuration (AES S1+SG4, ChaCha S1+SG16), Quartus 19.2 Pro, seed 6, the
retiming-pin constraint set (FPGA repo b8147cf), two cores.

- schoolbook: results/attic/c2w4t16.combined.schoolbook, vortexCrypto
  d1fb13323 -- ghmul.sg4 as a 4x4 schoolbook of clmul32 per quad, one array
  per quad (64 clmul32 per core).
- karatsuba: results/c2w4t16.combined-karatsuba, fa60d0d06 -- two Karatsuba
  levels, 9 clmul32 per quad, still one array per quad. Setup -0.072 ns at
  Slow vid1 100C: the deeper XOR combine lengthened the critical path.
- shared: results/c2w4t16.combined (canonical), d97c021cd -- one 9-clmul
  array walks the four quads over four cycles. All 30 corners close.

Per-block ALMs (ghash, aes_round, chacha_xr, poly, dr16) are the sum over
both cores of the Quartus entity table rows auth_unit|g_blocks[0].auth_ghash,
sym_unit|g_blocks[0].sym_aes, sym_rot, auth_unit|g_blocks[0].auth_poly and
sym_unit|g_blocks[0].sym_chacha_sg16 ("ALMs needed", including children).
total_alm and registers from fit.summary; slack is the worst Vortex-domain
entry of sta.summary. cycles: rtlsim AES-GCM hw_s3g at the board
configuration (F/D off, 3-cycle caches, one bank), n=128 -- shared is
bit-identical to schoolbook at b=8 (107,944) and -0.16% at b=64
(215,814 vs 216,170); Karatsuba is purely combinational (same by
construction). Extension dALM = total_alm - 183,971 (crypto-free).
