# Poly1305-engine ceiling probe (2026-09-02)

Question: the ChaCha S2 row pairs its cipher engine with the lane-local
poly26.mac, and counters put 42% of its retired instructions in the
authenticator -- would a Poly1305 S2 engine take the S2-vs-SG16 marginal?

Method: impl 13 (chacha_poly_s2_noauth, commit 24ff672d3) is the S2 row
with every Poly1305 absorb deleted; init and finish still run (an engine
keeps key derivation and the tag add), the tag is wrong by design, and the
rows record through --expect-fail. Twelve gated rtlsim points at n=128,
b={1,2,4,16,32,64}, both impls in one build; three-point intercept fits.

Result (cycles/B):
  s2        small 1.420   large 1.807   (0.451 instr/B)
  s2_noauth small 1.477   large 1.890   (0.078 instr/B)

Deleting 83% of the instruction stream made the row 4-5% SLOWER. The MACs
execute in the shadow of the engine's eight-cycle double-rounds and the
row's memory traffic; their issue slots had nothing better to do, and the
work between engine ops evidently helps warp interleaving. The ceiling for
any Poly1305 engine is therefore <= 0: not worth building. The S2-vs-SG16
marginal tie (1.807 vs 1.728) is robust to the missing engine, and the
paper's V-A paragraph now states the measured result instead of the
speculation. Cross-check: s2's large slope at this commit reproduces the
dataset value (1.807) to three decimals.
