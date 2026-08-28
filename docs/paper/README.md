# HARE -- DAC draft

`main.tex` + `hare.bib`; the data tables and the width figure under
`tables/` are **generated** -- edit `gen_tables.py`, not the `.tex` files:

    python3 gen_tables.py     # reads ../proposals/data/crypto_measurements.csv
                              # and $RESULTS (the DE10-Pro results dir)
    latexmk -pdf main.tex

Every number in the tables traces to one of two sources: the committed
per-run measurement CSV, or an archived Quartus `fit.summary`/`sta.summary`
under `fpga_proj/PCIE_DDR4_Vortex_G3X16/results/`. The generator autofills
from the reports when present and falls back to the values read on
2026-08-29 (printed to stderr when it does).

Decisions of record:

- No absolute Gb/s in abstract/intro/tables; cycles-per-byte and
  relative speedups only. One absolute anchor sentence in Sec. VI-A with
  the per-core figure.
- dALM is measured against the crypto-free build (183,971 ALMs), not the
  tree's "base" build -- base already contains the AES lane-local units.
- The sg16 area figure is the 2R1W build (223,427); the R4 predecessor
  (223,209) is preserved as results/c2w4t16.sg16-r4.
- The GPU-TEE overhead numbers (12.69x etc.) are deliberately NOT cited in
  the intro; the two arXiv papers appear once in related work, no numbers.
- bib entries marked TODO-verify need checking before submission.
