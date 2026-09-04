#!/usr/bin/env bash
# U7 performance sweep on the Combined bitstream: every Table II row that
# bitstream can host, at the paper's fit points, 5 warm-ups + 30 runs each.
#   AES-GCM   : i0 sw_ttable (S0), i1 hw_s1 (S1), i8 hw_s3g (S3/4)
#               b = 2,4,8 (4-16 KiB) and 64,128,256 (128-512 KiB)
#   ChaCha    : i0 sw and i1 rori (both S0 candidates), i7 s1, i12 sg16
#               b = 1,2,4 (8-32 KiB) and 16,32,64 (128-512 KiB)
# S2 rows and the ChaCha SG4 / arx16 rows need their own bitstreams
# (board_swap.sh) and run with the same script, --bitstream <name>.
set -uo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
OUT=${1:-docs/proposals/data/board-u7-$(date +%Y%m%d).csv}
[[ -c /dev/intel_fpga_pcie_drv && -w /dev/intel_fpga_pcie_drv ]] \
    || { echo "ERROR: /dev/intel_fpga_pcie_drv missing or not writable (insmod + chmod 666)" >&2; exit 1; }
echo "=== U7 combined sweep -> $OUT  ($(date))"
python3 tests/crypto/board_sweep.py --app aes_gcm     --impls 0,1,8      --blocks 2,4,8,64,128,256 --bitstream combined --out "$OUT"
python3 tests/crypto/board_sweep.py --app chacha_poly --impls 0,1,7,12   --blocks 1,2,4,16,32,64   --bitstream combined --out "$OUT"
echo "=== U7 COMBINED DONE ($(date)); rows: $(($(wc -l < "$OUT") - 1))"
