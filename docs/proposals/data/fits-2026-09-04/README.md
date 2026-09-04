# Same-version fits of record (2026-09-04)

Ten builds, Quartus 19.2 Pro, Stratix 10 1SG280HU1F50E1VG, seed 6, identical
RTL (vortexCrypto d97c021cd..b08f6f30d; the commits between are docs-only,
and each fit stamps the HEAD it started at). Nine use the constraint set of
FPGA commit b8147cf -- the single dispatch-buffer retiming exclusion that
closes Combined's hold corner. The AES S2 comparator (c2w4t16.s2p) is
fitted WITHOUT that exclusion: under it the build misses setup by up to
228 ps on three hot corners (TNS -6.5 ns, a path family); without it every
corner closes, as it did on the 09-01 set. The paper reports timing and
area only; this file is where that constraint difference is recorded, and
results/attic/c2w4t16.s2p.pinned keeps the failing fit.

build                     ALMs      regs worst_slack  stamp
c2w4t16.nocrypto       183,971    358776       0.000  d1fb13323
c2w4t16.base           208,764    377905       0.000  0b475affd
c2w4t16.chacha-s1      215,930    397516       0.000  72965c58d
c2w4t16.chacha-s3f     219,279    413849       0.000  b08f6f30d
c2w4t16                221,984    413142       0.000  b08f6f30d
c2w4t16.arx16          222,237    432217       0.000  b08f6f30d
c2w4t16.sg4            224,549    405511       0.000  6b2e314c2
c2w4t16.chacha-s2p     295,488    557318       0.000  b08f6f30d
c2w4t16.s2p            289,089    519409       0.000  a2ae92d60
c2w4t16.combined       238,526    429048       0.000  d97c021cd

GHASH stages: ghash-area-2026-09-03.{csv,md}. S0 rori finding:
chacha-s0-rori-20260903.md. Board cross-check: board-vs-rtlsim-20260903.md.
