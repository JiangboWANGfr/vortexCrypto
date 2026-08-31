#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include <crypto/vx_chacha.h>
#include "common.h"

// Deliberately issues chacha.dr.sg16 on a subgroup that is not whole.
//
// The double round reads the whole sixteen-lane state -- lane i's result
// depends on words other lanes hold -- so a partial mask would read an
// inactive lane's stale register and return a wrong state with nothing to
// show for it. This is the sixteen-lane twin of tests/crypto/torn_quad:
// lane 15 of every subgroup drops out and the instruction is issued anyway,
// which is the case the guards in VX_sym_chacha_sg16 and SimX's subgroup
// check exist for.
//
// The program is expected to be REJECTED, not to produce a number.
// ci/crypto_torn_sg16.sh runs it on both models and fails if either one
// lets it through.

__kernel void torn_sg16(kernel_arg_t* __UNIFORM__ arg) {
  uint32_t* src = (uint32_t*)arg->src;
  uint32_t* dst = (uint32_t*)arg->dst;
  const uint32_t t = threadIdx.x;

  // Every lane publishes a distinguishable value first, while the warp is
  // still converged, so a stale read has something recognisable to pick up.
  src[t] = 0xA5000000u | t;
  dst[t] = 0;
  __syncthreads();

  // Lane 15 of each subgroup drops out: mask 0111_1111_1111_1111, which is
  // exactly what the precondition forbids.
  if ((t & 15u) != 15u) {
    dst[t] = vx_chacha_dr_sg16(src[t]);
  }
}
