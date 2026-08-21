#!/bin/bash
# The torn-quad probe must be REJECTED by both models.
#
# tests/crypto/torn_quad issues chadd.sg4 on quads whose thread mask is 0111.
# Before the guard in VX_sym_rot and sym_unit.cpp, lane 2 read lane 3's stale
# register and returned a wrong answer with nothing to show for it. This
# inverts the usual sense: a clean exit is the failure.
set -e

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUILD=${BUILD:-$ROOT/build32}
DIR=$BUILD/tests/crypto/torn_quad
CONFIGS=${CONFIGS:-"-DVX_CFG_EXT_SYM_ENABLE -DVX_CFG_EXT_AUTH_ENABLE \
 -DVX_CFG_EXT_SYM_CHACHA_ENABLE -DVX_CFG_EXT_SYM_CHACHA_SG4_ENABLE"}

fail=0
for driver in simx rtlsim; do
    out=$(make -C "$DIR" "run-$driver" CONFIGS="$CONFIGS" 2>&1) && rc=0 || rc=$?

    if [ "$rc" -eq 0 ]; then
        echo "FAIL [$driver]: the torn-quad probe was accepted" >&2
        echo "$out" | tail -20 >&2
        fail=1
        continue
    fi
    if echo "$out" | grep -qi "SKIPPED"; then
        echo "SKIP [$driver]: $(echo "$out" | grep -i SKIPPED | head -1)"
        continue
    fi
    # Rejected -- but it has to be rejected for the right reason. A build
    # failure or a timeout also exits non-zero.
    if echo "$out" | grep -q "partially active quad"; then
        echo "PASS [$driver]: rejected, $(echo "$out" | grep -o 'partially active quad.*' | head -1)"
    elif echo "$out" | grep -q "VX_sym_rot.sv.*Assertion failed"; then
        echo "PASS [$driver]: rejected on VX_sym_rot's quad assertion"
    else
        echo "FAIL [$driver]: exited $rc, but not on the quad guard" >&2
        echo "$out" | tail -20 >&2
        fail=1
    fi
done
exit $fail
