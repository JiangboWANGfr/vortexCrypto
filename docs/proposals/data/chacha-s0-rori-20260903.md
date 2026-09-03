# ChaCha S0: plain software vs the rori row (2026-09-03)

Prompted by a draft sentence claiming the S0 figure "moves only 2.4%"
without rotate instructions -- a number from the superseded n=64 dataset
that the frozen dataset cannot support (it has no sw rows). Measured at
n=128, rtlsim, shape c2w4t16, the chacha-s1 build configuration, the two
S0 fit points:

  impl   b=16 cycles   b=32 cycles   large 2pt slope
  sw       1,469,082     2,779,520    9.998 c/B
  rori     1,671,111     3,168,524   11.424 c/B   (Table II's S0 row)

Plain software is 12.5% FASTER per byte than the rori variant, and 12%
faster in total at b=16 as well. The rori implementation in this ISA is
issued to the crypto SYM unit ("issues RORI, so requires EX_SYM" in the
host's impl table), not the integer ALU, so its one instruction costs more
than the three-instruction slli/srli/or idiom it replaces.

Consequences, for decision:
1. The draft sentence is removed -- unsupported and wrong in direction.
2. The S0 row of record (rori) was chosen as "the stronger software
   baseline"; in measurement it is the WEAKER one. Against plain sw the
   ChaCha S0->S1 step is 9.998/7.389 = 1.35x, not 1.55x, and the rori row
   is not attainable on a machine without the crypto extension at all.
   Making sw the S0 row would be the conservative choice for every ChaCha
   speedup. Not changed here; the dataset's S0 rows are frozen and this
   is the author's call.
