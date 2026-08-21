#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include <crypto/vx_chacha.h>
#include "common.h"

// Deliberately issues a subgroup instruction on a quad that is not whole.
//
// chadd.sg4 reads rs2 from lane (i & ~3) | ((i + 1) & 3) -- its neighbour
// inside the aligned quad. That is only meaningful if the quad is whole. This
// kernel makes lane 3 of every quad inactive and then issues it anyway, which
// is the case the guard in VX_sym_rot exists for: before the guard, lane 2 read
// lane 3's stale register and returned a wrong answer with nothing to show for
// it.
//
// The program is expected to be REJECTED, not to produce a number. Both models
// stop on it: rtlsim on VX_sym_rot's RUNTIME_ASSERT, SimX on check_quad_uniform.
// ci/crypto_torn_quad.sh runs it and fails if either one lets it through.

__kernel void torn_quad(kernel_arg_t* __UNIFORM__ arg) {
  uint32_t* src = (uint32_t*)arg->src;
  uint32_t* dst = (uint32_t*)arg->dst;
  const uint32_t t = threadIdx.x;

  // Every lane publishes a distinguishable value first, while the warp is
  // still converged, so a stale read has something recognisable to pick up.
  src[t] = 0xA5000000u | t;
  dst[t] = 0;
  __syncthreads();

  // Lane 3 of each quad drops out: mask 0111 per quad, which is exactly what
  // the rule forbids.
  if ((t & 3u) != 3u) {
    dst[t] = vx_chadd_sg4(t, src[t]);
  }
}
