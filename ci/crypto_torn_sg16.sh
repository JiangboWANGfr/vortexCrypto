#!/bin/bash
# The torn-sg16 probe must be REJECTED by both models.
#
# tests/crypto/torn_sg16 issues chacha.dr.sg16 on subgroups whose thread mask
# is 0x7fff. The double round reads the whole sixteen-lane state, so a partial
# mask would read an inactive lane's stale register and return a wrong state
# silently. This inverts the usual sense: a clean exit is the failure.
set -e

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUILD=${BUILD:-$ROOT/build32}
DIR=$BUILD/tests/crypto/torn_sg16
CONFIGS=${CONFIGS:-"-DVX_CFG_EXT_SYM_ENABLE -DVX_CFG_EXT_SYM_CHACHA_ENABLE \
 -DVX_CFG_EXT_SYM_CHACHA_SG16_ENABLE -DVX_CFG_NUM_THREADS=16"}

fail=0
for driver in simx rtlsim; do
    out=$(make -C "$DIR" "run-$driver" CONFIGS="$CONFIGS" 2>&1) && rc=0 || rc=$?

    if [ "$rc" -eq 0 ]; then
        echo "FAIL [$driver]: the torn-sg16 probe was accepted" >&2
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
    if echo "$out" | grep -q "partially active subgroup"; then
        echo "PASS [$driver]: rejected, $(echo "$out" | grep -o 'partially active subgroup.*' | head -1)"
    elif echo "$out" | grep -q "VX_sym_chacha_sg16.sv.*Assertion failed"; then
        echo "PASS [$driver]: rejected on VX_sym_chacha_sg16's assertion"
    else
        echo "FAIL [$driver]: exited $rc, but not on the subgroup guard" >&2
        echo "$out" | tail -20 >&2
        fail=1
    fi
done
exit $fail
