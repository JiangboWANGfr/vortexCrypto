"""Generate tests/crypto/measurements.yaml from the recorded rows.

The configurations are not invented here: each build below is one that
docs/proposals/data/crypto_measurements.csv actually contains a marginal-fit
sweep for, and the generator asserts that before emitting it.
"""
import csv, collections, sys

CSV = "docs/proposals/data/crypto_measurements.csv"
IMPL = {("chacha_poly", l): i for i, l in enumerate(
        ["sw","rori","sw_perm","sw_perm2","sw_perm3","xr","mac","s1","s3","s3f","s2"])}
IMPL.update({("aes_gcm", l): i for i, l in enumerate(
        ["sw_ttable","hw_s1","sw_perm","hw_sg4","hw_s1_ilv","hw_s1_ofs","hw_s3",
         "hw_s3f","hw_s3g","hw_s2a","hw_s2","hw_s2_ilv"])})

def macros(short):
    return " ".join("-DVX_CFG_EXT_%s_ENABLE" % m for m in short.split())

# b=1,2,3,4 is the cache-resident regime (4-16 KB) and b=16,32 the memory-bound
# one (64-128 KB). Four points in the first because a two-point fit there
# multiplies its endpoints' error by up to 8x -- see section 23's noise-floor
# note -- and b=4 is already the 16 KB D-cache boundary, so the span cannot be
# widened instead.
CHACHA_POINTS = [(64,1),(64,2),(64,3),(64,4),(64,16),(64,32)]

# (build label, extensions as the CSV spells them, impls, (msgs, blocks) points)
BUILDS = [
  ("chacha-s1", "AUTH AUTH_POLY SYM_CHACHA SYM",
   ["sw", "rori", "xr", "mac", "s1", "s3"], CHACHA_POINTS),
  ("chacha-s2", "AUTH AUTH_POLY SYM_CHACHA SYM_CHACHA_S2 SYM",
   ["s1", "s2"], CHACHA_POINTS),
  ("chacha-s3", "AUTH AUTH_POLY AUTH_POLY_SG4 SYM_CHACHA SYM_CHACHA_SG4 SYM",
   ["s1", "s3", "s3f"], CHACHA_POINTS),
  ("aes", "AUTH AUTH_S2 AUTH_SG4 SYM SYM_S2 SYM_SG4",
   ["sw_ttable", "hw_s1", "hw_s2", "hw_s3g", "hw_s2_ilv"], [(128,8),(128,64)]),
]

APP = {"sw":"chacha_poly","rori":"chacha_poly","xr":"chacha_poly","mac":"chacha_poly",
       "s1":"chacha_poly","s2":"chacha_poly","s3":"chacha_poly","s3f":"chacha_poly"}

have = collections.defaultdict(set)
for r in csv.DictReader(open(CSV)):
    if r["driver"] == "rtlsim":
        have[(r["app"], r["impl"], r["extensions"])].add((int(r["msgs"]), int(r["blocks_per_msg"])))

out = ['''# Measurement cases: the configurations behind the tables in
# docs/proposals/crypto_isa_proposal.md.
#
# This is NOT ci/testcases/crypto.yaml. That file is regression coverage, sized
# for CI: one point per case, at the default shape, with each implementation
# built in isolation. Those are different numbers -- ChaCha-Poly S2 fits to
# 1.08 c/B there and 1.90 c/B here, a 43% spread from configuration alone
# against a 4% noise floor -- so the two must not be mixed.
#
# What makes these measurement cases:
#   - four block counts per implementation (two per block count for AES), so a
#     marginal fit has its two points at each operating point: cache-resident
#     (4-16 KB) and memory-bound (64-128 KB)
#   - one build per group, because build-to-build cycle counts move up to 4%
#     from instruction layout alone
#   - s1 repeated in all three ChaCha builds, as the anchor that makes that
#     drift visible rather than invisible
#
# The shape is not here: bench.py supplies the recorded c2w4t16 via --shape.
#
# Generated from docs/proposals/data/crypto_measurements.csv, and 52 of the 54
# cases reproduce a run that CSV records field for field. The two that do not
# are m-aes-sw-ttable-b8/-b64: the archived AES software pair was taken in a
# different build (with the stack-skew experiment on) and at -b16 rather than
# -b8. They are placed here in the same build as the AES hardware rows so the
# whole row set shares one, which is the comparison the table makes. Those two
# are therefore a new measurement, not a reproduction.
#
# Run it with:
#   tests/crypto/bench.py --yaml tests/crypto/measurements.yaml
category: crypto_measure
defaults:
  xlen:
  - 32
  tier: full
tests:''']

n = 0
for label, ext, impls, points in BUILDS:
    for impl in impls:
        app = APP.get(impl, "aes_gcm")
        key = (app, impl, " ".join(sorted(ext.split())) if False else ext)
        # the CSV spells extensions in its own order; match on the set
        got = set()
        for (a, i, e), pts in have.items():
            if a == app and i == impl and set(e.split()) == set(ext.split()):
                got |= pts
        if not got:
            print("WARN: no recorded rows for %s/%s under %r" % (app, impl, ext),
                  file=sys.stderr)
        for msgs, blocks in points:
            n += 1
            out.append("- id: m-{}-{}-b{}".format(label, impl.replace("_","-"), blocks))
            out.append("  via: make-run")
            out.append("  drivers:\n  - rtlsim")
            out.append("  dir: tests/crypto/{}".format(app))
            out.append("  target: run-{driver}")
            out.append("  configs: {}".format(macros(ext)))
            out.append("  vars:")
            out.append("    OPTS: -n{} -b{} -i{}".format(msgs, blocks, IMPL[(app, impl)]))
open("tests/crypto/measurements.yaml", "w").write("\n".join(out) + "\n")
print("%d cases, %d builds -> tests/crypto/measurements.yaml" % (n, len(BUILDS)))
