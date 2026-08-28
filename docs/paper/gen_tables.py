#!/usr/bin/env python3
"""Regenerate the paper's data tables from the committed measurement record.

Every number in tables/*.tex traces to one of two sources:

  1. docs/proposals/data/crypto_measurements.csv   (cycles, instructions)
  2. the archived Quartus reports under $RESULTS    (ALMs, registers, slack)

Run from anywhere; writes docs/paper/tables/*.tex.  If a results directory is
missing, the script falls back to the values read from those same reports on
2026-08-29 and says so, so the tables never silently change meaning.
"""
import csv, io, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(HERE, "..", "proposals", "data", "crypto_measurements.csv")
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

# ---------------------------------------------------------------- fits ----
R = list(csv.DictReader(io.open(CSV, encoding="utf-8")))

def marginal(app, impl, batch, extmark, lo, hi):
    """Two-point marginal fit between blocks_per_msg lo and hi."""
    g = {}
    for r in R:
        if (r["app"], r["impl"], r["driver"]) != (app, impl, "rtlsim"):
            continue
        if not r["log"].startswith(batch):
            continue
        if extmark and extmark not in r["extensions"]:
            continue
        g[int(r["blocks_per_msg"])] = (int(r["cycles"]), int(r["instrs"]),
                                       int(r["bytes"]))
    if lo not in g or hi not in g:
        raise SystemExit(f"missing rows for {app}/{impl} b={lo},{hi} in {batch}")
    dc = g[hi][0] - g[lo][0]
    di = g[hi][1] - g[lo][1]
    db = g[hi][2] - g[lo][2]
    return dc / db, di / db, dc, db   # c/B, i/B (and raw deltas for checks)

# app, impl, batch, extension marker, (cache pair), (mem pair)
SPEC = {
  ("AES-GCM", "S0"):        ("aes_gcm", "sw_ttable", "paper16/", "SG4",  2,  8, 32, 64),
  ("AES-GCM", "S1"):        ("aes_gcm", "hw_s1",     "paper16/", "SG4",  2,  8, 32, 64),
  ("AES-GCM", "S2"):        ("aes_gcm", "hw_s2",     "paper16/", "SG4",  2,  8, 32, 64),
  ("AES-GCM", "S3/4"):      ("aes_gcm", "hw_s3g",    "paper16/", "SG4",  2,  8, 32, 64),
  ("ChaCha-Poly", "S0"):    ("chacha_poly", "rori",  "paper16/", "SG4",  1,  4, 16, 32),
  ("ChaCha-Poly", "S1"):    ("chacha_poly", "s1",    "paper16/", "SG4",  1,  4, 16, 32),
  ("ChaCha-Poly", "S2"):    ("chacha_poly", "s2",    "paper16/", "SG4",  1,  4, 16, 32),
  ("ChaCha-Poly", "S3/4"):  ("chacha_poly", "s3f",   "paper16/", "SG4",  1,  4, 16, 32),
  ("ChaCha-Poly", "S3/16"): ("chacha_poly", "sg16",  "paper16/", "SG16", 1,  4, 16, 32),
  ("ChaCha-Poly", "ARX16"): ("chacha_poly", "sg16",  "arx16/",   "ARX16",1,  4, 16, 32),
}

FIT = {}
for k, (app, impl, batch, mark, cl, ch, ml, mh) in SPEC.items():
    cb, ib, _, _ = marginal(app, impl, batch, mark, ml, mh)
    ccb, cib, _, _ = marginal(app, impl, batch, mark, cl, ch)
    FIT[k] = dict(mem_cb=cb, mem_ib=ib, cache_cb=ccb)

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
    s0 = FIT[(algo, "S0")]["mem_cb"]
    s1 = FIT[(algo, "S1")]["mem_cb"]
    tiers = ["S0", "S1", "S2", "S3/4"] + (["S3/16"] if algo == "ChaCha-Poly" else [])
    names = {"S0": "S0 software", "S1": "S1 lane-local",
             "S2": "S2 stateful engine", "S3/4": "S3 subgroup\\,/\\,4",
             "S3/16": "S3 subgroup\\,/\\,16"}
    for i, t in enumerate(tiers):
        f = FIT[(algo, t)]
        b = ROW_BUILD[(algo, t)]
        d = "0" if b is None else f"+{com(AREA[b][0]-ZERO)}"
        best = (algo == "AES-GCM" and t == "S3/4") or t == "S3/16"
        bb = lambda s: f"\\textbf{{{s}}}" if best else s
        rows.append(" & ".join([
            algo if i == 0 else "",
            bb(names[t]),
            bb(fmt(f["mem_cb"])), fmt(f["mem_ib"]),
            bb(fmt(s0 / f["mem_cb"], 2)), bb(fmt(s1 / f["mem_cb"], 2)),
            d]) + r" \\")
    rows.append(r"\midrule" if algo == "AES-GCM" else "")

tab2 = r"""%% generated by gen_tables.py -- do not edit
\begin{tabular}{@{}llrrrrr@{}}
\toprule
 & Tier & c/B & instr/B & $\times$S0 & $\times$S1 & $\Delta$ALM \\
\midrule
""" + "\n".join(r for r in rows if r) + "\n" + r"""\bottomrule
\end{tabular}
"""

# ------------------------------------------------------------- table 3 ----
arx, dr, s2 = FIT[("ChaCha-Poly","ARX16")], FIT[("ChaCha-Poly","S3/16")], FIT[("ChaCha-Poly","S2")]
t3rows = [
 ("none (\\texttt{chacha.arx.sg16})", "0",
   fmt(arx["mem_ib"]*64,1), fmt(arx["mem_cb"]*64,1), com(AREA["c2w4t16.arx16"][0])),
 ("\\textbf{working regs (\\texttt{chacha.dr.sg16})}", "\\textbf{1{,}154}",
   f"\\textbf{{{fmt(dr['mem_ib']*64,1)}}}", f"\\textbf{{{fmt(dr['mem_cb']*64,1)}}}",
   f"\\textbf{{{com(AREA['c2w4t16'][0])}}}"),
 ("architectural context (S2)", "57{,}344",
   fmt(s2["mem_ib"]*64,1), fmt(s2["mem_cb"]*64,1), com(AREA["c2w4t16.chacha-s2p"][0])),
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

# ------------------------------------------------------------- fig 2 -----
sp = lambda k: FIT[("ChaCha-Poly","S1")]["mem_cb"]/FIT[("ChaCha-Poly",k)]["mem_cb"]
spa = FIT[("AES-GCM","S1")]["mem_cb"]/FIT[("AES-GCM","S3/4")]["mem_cb"]
c4, c16 = sp("S3/4"), sp("S3/16")
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
                ("tab_area.tex", tab4), ("fig_width.tex", fig)]:
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
for k in SPEC:
    f = FIT[k]
    print(f"{k}: mem {f['mem_cb']:.3f} c/B  {f['mem_ib']:.3f} i/B   cache {f['cache_cb']:.3f} c/B")
