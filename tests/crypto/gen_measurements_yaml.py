"""Generate the crypto measurement catalogs from the recorded rows.

Writes three files, and the split is the point:

  measurements.yaml   the paper's S0-S3 matrix, one build per algorithm
  ablation.yaml       the rows that explain a tier rather than define one
  probe_build_merge.yaml  the evidence that one build per algorithm is safe

Every implementation reported with a cache-resident and a memory-bound marginal
is measured at the same four payload sizes: 4, 16, 64 and 128 KiB. No row gets
more points than another, and none gets fewer -- deciding measurement density
from the speedup a row turned out to have would be sampling on the outcome.
"""
import csv, collections, sys

CSV = "docs/proposals/data/crypto_measurements.csv"

# A block is 16 bytes for aes_gcm and 64 for chacha_poly, so the grid is in
# payload bytes and the block counts differ to match.
#
#     4 KiB   16 KiB  |  64 KiB  128 KiB
#     ---cache-resident---|---memory-bound---
#     chacha  b=1  b=4    |  b=16   b=32   (n=64)
#     aes     b=2  b=8    |  b=32   b=64   (n=128)
GRID = {"chacha_poly": (64, [1, 4, 16, 32]), "aes_gcm": (128, [2, 8, 32, 64])}

IMPL = {("chacha_poly", l): i for i, l in enumerate(
        ["sw","rori","sw_perm","sw_perm2","sw_perm3","xr","mac","s1","s3","s3f","s2"])}
IMPL.update({("aes_gcm", l): i for i, l in enumerate(
        ["sw_ttable","hw_s1","sw_perm","hw_sg4","hw_s1_ilv","hw_s1_ofs","hw_s3",
         "hw_s3f","hw_s3g","hw_s2a","hw_s2","hw_s2_ilv"])})

# One build per algorithm, every tier reachable through -i. ChaCha needed three
# narrow builds only as an artefact of how its extensions were brought up; the
# all-on build runs all of them, compiles byte-identical code (every instruction
# count matches the narrow builds to the digit), and reproduces all three tier
# speedups inside the noise floor. With one build there is no cross-build
# comparison left to correct for, and so no S1 anchor to repeat.
CHACHA = "AUTH AUTH_POLY AUTH_POLY_SG4 SYM_CHACHA SYM_CHACHA_S2 SYM_CHACHA_SG4 SYM"
AES    = "AUTH AUTH_S2 AUTH_SG4 SYM SYM_S2 SYM_SG4"

# tier -> (app, impl). S0 for ChaCha is `rori`, not `sw`: RORI is ratified
# Zbb/Zbkb, and crediting the B extension to a cryptographic ISE would be false.
PAPER = [("aes_gcm", AES,    [("S0","sw_ttable"),("S1","hw_s1"),
                              ("S2","hw_s2"),("S3","hw_s3g")]),
         ("chacha_poly", CHACHA, [("S0","rori"),("S1","s1"),
                                  ("S2","s2"),("S3","s3f")])]

# Rows that explain a tier rather than define one.
ABLATION = [
  ("chacha_poly", CHACHA, [("sw","pure software, below the RORI baseline"),
                           ("xr","S1 without poly26.mac"),
                           ("mac","S1 without chacha32.xr"),
                           ("s3","the S3 layout before its routing is fused")]),
  ("aes_gcm", AES, [("hw_s2_ilv","S2 with the interleaved payload layout")]),
]

def macros(short):
    return " ".join("-DVX_CFG_EXT_%s_ENABLE" % m for m in short.split())

def emit(path, header, groups):
    out = [header]
    n = 0
    for app, ext, rows in groups:
        msgs, blocks = GRID[app]
        for label, note in rows:
            for b in blocks:
                n += 1
                out += [f"- id: {label}-{app.split('_')[0]}-b{b}",
                        "  via: make-run", "  drivers:", "  - rtlsim",
                        f"  dir: tests/crypto/{app}", "  target: run-{driver}",
                        f"  configs: {macros(ext)}", "  vars:",
                        f"    OPTS: -n{msgs} -b{b} -i{IMPL[(app, note if (app,note) in IMPL else label)]}"]
    open(path, "w").write("\n".join(out) + "\n")
    return n

HEAD = """# {what}
#
# NOT ci/testcases/crypto.yaml. That file is regression coverage, sized for CI:
# one point per case, at the default shape, each implementation built alone.
# Those are different numbers -- ChaCha-Poly S2 fits to 1.08 c/B there and
# 1.90 c/B in the configuration the document reports, a 43% spread from
# configuration alone against a noise floor of 3% (memory-bound) to 9%
# (cache-resident). The two must not share a records.csv.
#
# One build per algorithm; the tier is chosen with -i. Four payload sizes for
# every row: 4, 16, 64 and 128 KiB, which is b=1,4,16,32 for chacha_poly and
# b=2,8,32,64 for aes_gcm, the block being 64 bytes for one and 16 for the
# other. The first pair is the cache-resident marginal, the second the
# memory-bound one.
#
# The shape is not here: bench.py supplies the recorded c2w4t16 via --shape.
#
#   tests/crypto/bench.py --yaml tests/crypto/{f} --runs build32/crypto_runs/{d}
category: {cat}
defaults:
  xlen:
  - 32
  tier: full
tests:"""

paper = [(a, e, [(l, i) for l, i in rows]) for a, e, rows in PAPER]
abl   = [(a, e, [(i, i) for i, _ in rows]) for a, e, rows in ABLATION]
# paper rows are labelled by tier but keyed by impl
paper = [(a, e, [(i, i) for _, i in rows]) for a, e, rows in PAPER]

n1 = emit("tests/crypto/measurements.yaml",
          HEAD.format(what="The paper's S0-S3 matrix.", f="measurements.yaml",
                      d="measure", cat="crypto_measure"), paper)
n2 = emit("tests/crypto/ablation.yaml",
          HEAD.format(what="Rows that explain a tier rather than define one.",
                      f="ablation.yaml", d="ablation", cat="crypto_ablation"), abl)
print(f"measurements.yaml {n1} cases (2 builds), ablation.yaml {n2} cases")
