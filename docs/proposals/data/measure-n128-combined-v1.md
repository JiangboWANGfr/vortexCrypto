# Combined-build anchor cross-check (U4), 2026-08-31

24 gated rtlsim rows at n=128, commit bbcda4761 (clean tree): the S1
anchors and HARE headline implementations of both algorithms, re-measured
in the single deployable Combined HARE build
(SYM+AUTH + SYM_SG4/AUTH_SG4 + SYM_CHACHA/AUTH_POLY +
SYM_CHACHA_SG16/AUTH_POLY_STEP16), at every fit b-point of dataset
measure-n128-2r1w-v2.

Result, same estimator as the dataset (three-point intercept fits, S3/16
small keeps its endpoint chord): chacha s1, chacha sg16, and aes hw_s1
slopes are BIT-IDENTICAL to their per-algorithm-build values in v2 (the
added idle units do not perturb unrelated code's timing in deterministic
simulation); aes hw_s3g moves +1.3% small / -1.5% large, inside the
recorded ~4% instruction-layout noise. Speedups: chacha 8.41x/4.32x
unchanged; aes 5.74x/4.99x vs v2's 5.81x/4.92x.

Verdict: no version-configuration mismatch between the performance
dataset (per-algorithm builds) and the deployable Combined configuration
that the final PPA reports. Headline numbers stay sourced from v2.
