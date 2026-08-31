#!/usr/bin/env python3
"""Regenerate the paper's data tables from the frozen measurement dataset.

Every number in tables/*.tex traces to one of two sources:

  1. docs/proposals/data/measure-n128-2r1w-v2.csv  (cycles, instructions),
     the gated n=128 dataset described by its .yaml sidecar
  2. the archived Quartus reports under $RESULTS   (ALMs, registers, slack)

The performance dataset is loaded through hard gates: schema version 2, the
recorded c2w4t16 shape, 128 messages, a git stamp the sidecar declares, an
even per-core instruction split (balance >= 0.90) in every row, and a config
hash matching the sidecar. The S3/16 rows take their S1 denominator from the
s1 anchor measured in the same build, never across builds.

Mainline tiers (S1, S2, and each algorithm's subgroup form) fit three points
per regime with an intercept, every point at a power-of-two blocks count
(small b=1,2,4 / 2,4,8; large b=16,32,64 / 32,64,128) -- a non-power-of-two
count gives every message a non-power-of-two stride and lands in a different
cache/DRAM conflict family (the b=24/48 rows in the dataset measure exactly
that, and no fit reads them). Each three-point slope must agree with the
original two-point pair (16,32)/(32,64) within 5%, and the middle point must
sit within 5% of the triplet's endpoint chord, or generation aborts. S0, the
ChaCha SG4 row, and the ARX16 ablation keep two-point fits on the original
pairs. Rows from the historical crypto_measurements.csv (n=64, mixed core
utilisation) are not read at all.

Run from anywhere; writes docs/paper/tables/*.tex.  If a results directory is
missing, the script falls back to the values read from those same reports on
2026-08-29 and says so, so the tables never silently change meaning.
"""
import csv, hashlib, io, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "proposals", "data")
DATASET = "measure-n128-2r1w-v2"
RESULTS = os.environ.get(
    "RESULTS",
    os.path.join(HERE, "..", "..", "..", "fpga_proj",
                 "PCIE_DDR4_Vortex_G3X16", "results"))
OUT = os.path.join(HERE, "tables")

# ---------------------------------------------------------------- area ----
# build-dir -> (ALMs, registers) read 2026-08-29; autofilled from RESULTS when
# present.  Worst Vortex-domain slack was >= 0.000 for every one of these.
FALLBACK = {
    "c2w4t16.nocrypto":   (183971, 358776),
    "c2w4t16.base":       (208513, 377741),
    "c2w4t16.chacha-s1":  (217383, 398476),
    "c2w4t16.chacha-s3f": (219921, 403240),
    "c2w4t16":            (223427, 417219),   # sg16, 2R1W poly
    "c2w4t16.arx16":      (217854, 413656),
    "c2w4t16.sg4":        (260938, 452906),
    "c2w4t16.chacha-s2p": (289353, 548422),
    "c2w4t16.s2p":        (299907, 562705),
}

def read_fit(build):
    d = os.path.join(RESULTS, build)
    f = os.path.join(d, "vortex_g3x16_ddr4x4.fit.summary")
    if not os.path.isfile(f):
        return None
    alm = regs = None
    for line in io.open(f, encoding="utf-8", errors="replace"):
        if "Logic utilization" in line and alm is None:
            alm = int(line.split(":")[1].split("/")[0].strip().replace(",", ""))
        if "dedicated logic registers" in line and regs is None:
            regs = int(line.split(":")[1].strip().replace(",", ""))
    return (alm, regs) if alm and regs else None

AREA = {}
for b, fb in FALLBACK.items():
    v = read_fit(b)
    AREA[b] = v if v else fb
    if not v:
        print(f"  (fallback) {b}: no fit.summary under RESULTS", file=sys.stderr)

ZERO = AREA["c2w4t16.nocrypto"][0]

# -------------------------------------------------------------- dataset ----
SCHEMA_V2 = ["app", "impl", "driver", "cores", "warps", "threads", "msgs",
             "blocks_per_msg", "blocks", "bytes", "cycles", "instrs",
             "core_instrs", "opts", "extensions", "git", "configs", "log"]

def read_meta(path):
    meta = {}
    for line in io.open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    return meta

def gate(cond, why):
    if not cond:
        raise SystemExit(f"dataset gate failed: {why}")

def load_dataset():
    meta = read_meta(os.path.join(DATA, DATASET + ".yaml"))
    gate(meta.get("dataset_id") == DATASET, "sidecar dataset_id mismatch")
    gate(meta.get("schema_version") == "2", "schema_version must be 2")
    gate(meta.get("operand_format") == "2R1W", "operand_format must be 2R1W")
    gate(meta.get("gate_passed") == "true", "sidecar says gate_passed != true")
    stamps = set(meta["recorded_git_stamps"].split())
    with io.open(os.path.join(DATA, DATASET + ".csv"), encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        gate(reader.fieldnames == SCHEMA_V2, "CSV columns are not schema v2")
        rows = list(reader)
    digest = hashlib.sha256(
        "\n".join(sorted({r["configs"] for r in rows})).encode()).hexdigest()
    gate("sha256:" + digest == meta["config_hash"], "config hash mismatch")
    for r in rows:
        gate(r["driver"] == "rtlsim", f"non-rtlsim row {r['log']}")
        gate((r["cores"], r["warps"], r["threads"]) == ("2", "4", "16"),
             f"off-shape row {r['log']}")
        gate(r["msgs"] == meta["n"], f"row at n={r['msgs']}, not {meta['n']}")
        gate(r["git"] in stamps, f"undeclared git stamp {r['git']}")
        parts = [int(p) for p in r["core_instrs"].split(":")]
        gate(min(parts) / max(parts) >= 0.90,
             f"core imbalance {parts} in {r['log']}")
    return rows

R = load_dataset()

def points(app, impl, extmark):
    """blocks_per_msg -> (cycles, instrs, bytes) within one build."""
    g, ext = {}, None
    for r in R:
        if (r["app"], r["impl"]) != (app, impl):
            continue
        if extmark not in r["extensions"].split():
            continue
        gate(ext in (None, r["extensions"]), f"{app}/{impl} spans builds")
        ext = r["extensions"]
        g[int(r["blocks_per_msg"])] = (int(r["cycles"]), int(r["instrs"]),
                                       int(r["bytes"]))
    return g, ext

def lsq(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    return (sum((x - mx) * (y - my) for x, y in zip(xs, ys)) /
            sum((x - mx) ** 2 for x in xs))

def fit_regime(g, bs, who, orig=None):
    """Slope of cycles and instrs over bytes across the given b points. A
    three-point fit must agree with the original two-point pair (default:
    the triplet's endpoints) within 5%, and the middle point must sit
    within 5% of the triplet's endpoint chord."""
    for b in bs:
        gate(b in g, f"missing b={b} for {who}")
    xs = [g[b][2] for b in bs]
    cyc = [g[b][0] for b in bs]
    ins = [g[b][1] for b in bs]
    slope = lsq(xs, cyc)
    if len(bs) >= 3:
        lo, hi = orig or (bs[0], bs[-1])
        two = (g[hi][0] - g[lo][0]) / (g[hi][2] - g[lo][2])
        gate(abs(slope - two) / two <= 0.05,
             f"{who}: 3-point slope {slope:.4f} vs original pair {two:.4f} "
             f"({100*abs(slope-two)/two:.1f}% apart)")
        chord = (cyc[-1] - cyc[0]) / (xs[-1] - xs[0])
        for x, y in zip(xs[1:-1], cyc[1:-1]):
            pred = cyc[0] + chord * (x - xs[0])
            gate(abs(y - pred) / pred <= 0.05,
                 f"{who}: middle point off the endpoint chord by "
                 f"{100*abs(y-pred)/pred:.1f}%")
    return slope, lsq(xs, ins)

# app, impl, build-selecting extension, small-regime b list, large-regime b list
CH3, CH2 = ([1, 2, 4], [16, 32, 64]), ([1, 4], [16, 32])
AE3, AE2 = ([2, 4, 8], [32, 64, 128]), ([2, 8], [32, 64])
ORIG = {"chacha_poly": (16, 32), "aes_gcm": (32, 64)}
SPEC = {
  ("AES-GCM", "S0"):        ("aes_gcm", "sw_ttable", "SYM_SG4") + AE2,
  ("AES-GCM", "S1"):        ("aes_gcm", "hw_s1",     "SYM_SG4") + AE3,
  ("AES-GCM", "S2"):        ("aes_gcm", "hw_s2",     "SYM_SG4") + AE3,
  ("AES-GCM", "S3/4"):      ("aes_gcm", "hw_s3g",    "SYM_SG4") + AE3,
  ("ChaCha-Poly", "S0"):    ("chacha_poly", "rori",  "SYM_CHACHA_SG4") + CH2,
  ("ChaCha-Poly", "S1"):    ("chacha_poly", "s1",    "SYM_CHACHA_SG4") + CH3,
  ("ChaCha-Poly", "S2"):    ("chacha_poly", "s2",    "SYM_CHACHA_SG4") + CH3,
  ("ChaCha-Poly", "S3/4"):  ("chacha_poly", "s3f",   "SYM_CHACHA_SG4") + CH2,
  ("ChaCha-Poly", "S1@16"): ("chacha_poly", "s1",    "SYM_CHACHA_SG16") + CH3,
  ("ChaCha-Poly", "S3/16"): ("chacha_poly", "sg16",  "SYM_CHACHA_SG16") + CH3,
  ("ChaCha-Poly", "ARX16"): ("chacha_poly", "sg16",  "SYM_CHACHA_ARX16") + CH2,
}

FIT, PTS = {}, {}
for k, (app, impl, mark, small, large) in SPEC.items():
    g, build = points(app, impl, mark)
    scb, sib = fit_regime(g, small, f"{k} small")
    lcb, lib = fit_regime(g, large, f"{k} large",
                          ORIG[app] if len(large) >= 3 else None)
    FIT[k] = dict(small_cb=scb, large_cb=lcb, large_ib=lib, build=build)
    PTS[k] = g

# The S3/16 speedups divide by the s1 measured in the same build, never the
# all-on s1: the gate is that anchor and subject share one extensions string.
gate(FIT[("ChaCha-Poly", "S1@16")]["build"] == FIT[("ChaCha-Poly", "S3/16")]["build"],
     "S3/16 and its S1 anchor come from different builds")

def s1_for(algo, tier):
    a = "S1@16" if (algo, tier) == ("ChaCha-Poly", "S3/16") else "S1"
    return FIT[(algo, a)]

# area attached to each tier row: build carrying that tier (cumulative).
ROW_BUILD = {
  ("AES-GCM", "S0"): None,            ("AES-GCM", "S1"): "c2w4t16.base",
  ("AES-GCM", "S2"): "c2w4t16.s2p",   ("AES-GCM", "S3/4"): "c2w4t16.sg4",
  ("ChaCha-Poly", "S0"): None,        ("ChaCha-Poly", "S1"): "c2w4t16.chacha-s1",
  ("ChaCha-Poly", "S2"): "c2w4t16.chacha-s2p",
  ("ChaCha-Poly", "S3/4"): "c2w4t16.chacha-s3f",
  ("ChaCha-Poly", "S3/16"): "c2w4t16",
}

def fmt(x, nd=3):  return f"{x:.{nd}f}"
def com(n):        return f"{n:,}"

# ------------------------------------------------------------- table 2 ----
rows = []
for algo in ("AES-GCM", "ChaCha-Poly"):
    tiers = ["S0", "S1", "S2", "S3/4"] + (["S3/16"] if algo == "ChaCha-Poly" else [])
    names = {"S0": "S0 software", "S1": "S1 lane-local",
             "S2": "S2 stateful engine", "S3/4": "S3 subgroup\\,/\\,4",
             "S3/16": "S3 subgroup\\,/\\,16"}
    for i, t in enumerate(tiers):
        f = FIT[(algo, t)]
        s1 = s1_for(algo, t)
        b = ROW_BUILD[(algo, t)]
        d = "0" if b is None else f"+{com(AREA[b][0]-ZERO)}"
        best = (algo == "AES-GCM" and t == "S3/4") or t == "S3/16"
        bb = lambda s: f"\\textbf{{{s}}}" if best else s
        rows.append(" & ".join([
            algo if i == 0 else "",
            bb(names[t]),
            bb(fmt(f["small_cb"])), bb(fmt(f["large_cb"])), fmt(f["large_ib"]),
            bb(fmt(s1["small_cb"] / f["small_cb"], 2)),
            bb(fmt(s1["large_cb"] / f["large_cb"], 2)),
            d]) + r" \\")
    rows.append(r"\midrule" if algo == "AES-GCM" else "")

tab2 = r"""%% generated by gen_tables.py -- do not edit
\begin{tabular}{@{}llrrrrrr@{}}
\toprule
 & Tier & \multicolumn{2}{c}{c/B} & instr/B & \multicolumn{2}{c}{$\times$S1} & $\Delta$ALM \\
 &      & small & large &         & small & large & \\
\midrule
""" + "\n".join(r for r in rows if r) + "\n" + r"""\bottomrule
\end{tabular}
"""

# ------------------------------------------------------------- table 3 ----
arx, dr, s2 = FIT[("ChaCha-Poly","ARX16")], FIT[("ChaCha-Poly","S3/16")], FIT[("ChaCha-Poly","S2")]
t3rows = [
 ("none (\\texttt{chacha.arx.sg16})", "0",
   fmt(arx["large_ib"]*64,1), fmt(arx["large_cb"]*64,1), com(AREA["c2w4t16.arx16"][0])),
 ("\\textbf{working regs (\\texttt{chacha.dr.sg16})}", "\\textbf{1{,}154}",
   f"\\textbf{{{fmt(dr['large_ib']*64,1)}}}", f"\\textbf{{{fmt(dr['large_cb']*64,1)}}}",
   f"\\textbf{{{com(AREA['c2w4t16'][0])}}}"),
 ("architectural context (S2)", "57{,}344",
   fmt(s2["large_ib"]*64,1), fmt(s2["large_cb"]*64,1), com(AREA["c2w4t16.chacha-s2p"][0])),
]
tab3 = r"""%% generated by gen_tables.py -- do not edit
\begin{tabular}{@{}lrrrr@{}}
\toprule
Where the state lives & bits & instr/64\,B & cyc/64\,B & ALMs \\
\midrule
""" + "\n".join(" & ".join(r) + r" \\" for r in t3rows) + "\n" + r"""\bottomrule
\end{tabular}
"""

# ------------------------------------------------------------- table 4 ----
t4 = [("crypto-free core",             "c2w4t16.nocrypto"),
      ("+ AES-GCM S1",                 "c2w4t16.base"),
      ("+ ChaCha-Poly S1",             "c2w4t16.chacha-s1"),
      ("+ ChaCha S3\\,/\\,4 pair",     "c2w4t16.chacha-s3f"),
      ("+ ChaCha S3\\,/\\,16 pair",    "c2w4t16"),
      ("\\quad stateless ablation",    "c2w4t16.arx16"),
      ("+ AES S3\\,/\\,4 pair",        "c2w4t16.sg4"),
      ("+ ChaCha S2 engines",          "c2w4t16.chacha-s2p"),
      ("+ AES S2 engines",             "c2w4t16.s2p")]
t4rows = []
for name, b in t4:
    a, r = AREA[b]
    d = "---" if b == "c2w4t16.nocrypto" else f"+{com(a-ZERO)}"
    t4rows.append(f"{name} & {com(a)} & {com(r)} & {d} \\\\")
tab4 = r"""%% generated by gen_tables.py -- do not edit
\begin{tabular}{@{}lrrr@{}}
\toprule
Build & ALMs & Registers & $\Delta$ALM \\
\midrule
""" + "\n".join(t4rows) + "\n" + r"""\bottomrule
\end{tabular}
"""

# ------------------------------------------------------------- table 5 ----
def step(algo, a, b, side):
    return fmt(FIT[(algo, a)][side] / FIT[(algo, b)][side], 2) + r"$\times$"

def s3(algo):  # each algorithm's best subgroup tier
    return "S3/4" if algo == "AES-GCM" else "S3/16"

t5rows = []
for label, a, b in [("S0 $\\to$ S1", "S0", "S1"), ("S1 $\\to$ S2", "S1", "S2"),
                    ("S2 $\\to$ S3", "S2", None), ("S0 $\\to$ S3", "S0", None)]:
    cells = [label]
    for algo in ("AES-GCM", "ChaCha-Poly"):
        bb = b or s3(algo)
        cells += [step(algo, a, bb, "large_cb"), step(algo, a, bb, "small_cb")]
    t5rows.append(" & ".join(cells) + r" \\")
tab5 = r"""%% generated by gen_tables.py -- do not edit
\begin{tabular}{@{}lrrrr@{}}
\toprule
 & \multicolumn{2}{c}{AES-GCM} & \multicolumn{2}{c}{ChaCha-Poly} \\
Step & large & small & large & small \\
\midrule
""" + "\n".join(t5rows) + "\n" + r"""\bottomrule
\end{tabular}
"""

# ------------------------------------------------------------- fig 2 -----
def sp16(k):
    return s1_for("ChaCha-Poly", k)["large_cb"] / FIT[("ChaCha-Poly", k)]["large_cb"]
spa = FIT[("AES-GCM","S1")]["large_cb"]/FIT[("AES-GCM","S3/4")]["large_cb"]
c4, c16 = sp16("S3/4"), sp16("S3/16")
SC = 0.62   # cm per 1x speedup
fig = rf"""%% generated by gen_tables.py -- do not edit
\begin{{tikzpicture}}[x=1cm,y={SC}cm, font=\footnotesize]
  \draw[->] (-0.2,0) -- (7.4,0) node[below left]{{}};
  \draw[->] (0,-0.05) -- (0,5.6*{1}) ;
  \foreach \y in {{1,2,3,4,5}} {{
    \draw (0,\y) -- (-0.1,\y) node[left]{{\y$\times$}};
    \draw[gray!30] (0,\y) -- (7.3,\y); }}
  \draw[dashed,gray] (0,1) -- (7.3,1);
  %% AES-GCM: state 128 b = 4 lanes
  \fill[black!55] (0.6,0) rectangle +(0.8,{spa:.3f});
  \node[above] at (1.0,{spa:.3f}) {{{spa:.2f}$\times$}};
  \node[below] at (1.0,0) {{SG4}};
  \node[below=14pt] at (1.0,0) {{\textbf{{AES-GCM}}}};
  \node[below=24pt] at (1.0,0) {{state 128\,b $=$ 4 lanes}};
  %% ChaCha: state 512 b = 16 lanes
  \fill[black!25] (3.6,0) rectangle +(0.8,{c4:.3f});
  \node[above] at (4.0,{c4:.3f}) {{{c4:.2f}$\times$}};
  \node[below] at (4.0,0) {{SG4}};
  \fill[black!55] (5.2,0) rectangle +(0.8,{c16:.3f});
  \node[above] at (5.6,{c16:.3f}) {{{c16:.2f}$\times$}};
  \node[below] at (5.6,0) {{SG16}};
  \node[below=14pt] at (4.8,0) {{\textbf{{ChaCha20-Poly1305}}}};
  \node[below=24pt] at (4.8,0) {{state 512\,b $=$ 16 lanes}};
\end{{tikzpicture}}
"""

os.makedirs(OUT, exist_ok=True)
for name, s in [("tab_tiers.tex", tab2), ("tab_state.tex", tab3),
                ("tab_area.tex", tab4), ("tab_steps.tex", tab5),
                ("fig_width.tex", fig)]:
    io.open(os.path.join(OUT, name), "w", encoding="utf-8", newline="\n").write(s)
    print("wrote tables/" + name)

# ------------------------------------------------------- prose numbers ----
print("\n--- numbers the prose cites (verify after any regen) ---")
print(f"zero (crypto-free)        : {com(ZERO)} ALMs")
print(f"S1 units (AES, parents)   : +{com(AREA['c2w4t16.base'][0]-ZERO)}")
print(f"SG16 pair over ChaCha S1  : +{com(AREA['c2w4t16'][0]-AREA['c2w4t16.chacha-s1'][0])}"
      f"  ({100*(AREA['c2w4t16'][0]-AREA['c2w4t16.chacha-s1'][0])/AREA['c2w4t16.chacha-s1'][0]:.1f}%)")
print(f"SG4 pair over AES S1      : +{com(AREA['c2w4t16.sg4'][0]-AREA['c2w4t16.base'][0])}"
      f"  ({100*(AREA['c2w4t16.sg4'][0]-AREA['c2w4t16.base'][0])/AREA['c2w4t16.base'][0]:.1f}%)")
print(f"ChaCha S2 dALM / S3-16 dALM: "
      f"{(AREA['c2w4t16.chacha-s2p'][0]-ZERO)/(AREA['c2w4t16'][0]-ZERO):.2f}x")
print(f"arx16/dr16 slowdown (large): "
      f"{FIT[('ChaCha-Poly','ARX16')]['large_cb']/FIT[('ChaCha-Poly','S3/16')]['large_cb']:.2f}x"
      f"  instrs {FIT[('ChaCha-Poly','ARX16')]['large_ib']/FIT[('ChaCha-Poly','S3/16')]['large_ib']:.2f}x")
print(f"sg16 vs s2 (large, small) : "
      f"{FIT[('ChaCha-Poly','S2')]['large_cb']/FIT[('ChaCha-Poly','S3/16')]['large_cb']:.2f}x, "
      f"{FIT[('ChaCha-Poly','S2')]['small_cb']/FIT[('ChaCha-Poly','S3/16')]['small_cb']:.2f}x")
print(f"MB/s at 200 MHz (large)   : AES S3 {200/FIT[('AES-GCM','S3/4')]['large_cb']:.0f}"
      f"  ChaCha S3/16 {200/FIT[('ChaCha-Poly','S3/16')]['large_cb']:.0f}"
      f"  AES sw {200/FIT[('AES-GCM','S0')]['large_cb']:.1f}"
      f"  ChaCha S0 {200/FIT[('ChaCha-Poly','S0')]['large_cb']:.1f}")
for k, b in [(("AES-GCM", "S3/4"), 8), (("AES-GCM", "S3/4"), 64),
             (("ChaCha-Poly", "S3/16"), 4), (("ChaCha-Poly", "S3/16"), 32),
             (("AES-GCM", "S1"), 64), (("ChaCha-Poly", "S1@16"), 32)]:
    c, _, d = PTS[k][b]
    print(f"whole-run {k} b={b}: {d} B in {c} cycles = {d/c:.3f} B/c "
          f"({d/c*200:.0f} MB/s at 200 MHz)")
for k in SPEC:
    f = FIT[k]
    print(f"{k}: large {f['large_cb']:.3f} c/B  {f['large_ib']:.3f} i/B   "
          f"small {f['small_cb']:.3f} c/B")
