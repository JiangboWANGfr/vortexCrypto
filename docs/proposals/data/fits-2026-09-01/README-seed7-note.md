# Combined seed comparison (2026-09-02)

seed 6: 278,495 ALMs, vortex-domain worst slack -0.002 (one endpoint, one
corner, hold, Slow vid1 0C; endpoint TNS -0.002 so exactly one path).
seed 7: 277,573 ALMs, worst slack -0.082.

Seed 7 was run to chase the 2 ps hold corner and made it worse; seed 6 is
the build of record and the paper discloses both. QSF reverted to SEED 6
(FPGA repo history carries the seed-7 commit for provenance).
