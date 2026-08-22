#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include <crypto/vx_chacha.h>
#include "common.h"

// Exercises chacha.dr.sg16 against a host reference. One aligned sixteen-lane
// subgroup holds one 512-bit state, lane i carrying word i, and one instruction
// advances a double-round.

__kernel void cha16_probe(kernel_arg_t* __UNIFORM__ arg) {
  const uint32_t* in = (const uint32_t*)arg->in;
  uint32_t* out = (uint32_t*)arg->out;
  const uint32_t t = threadIdx.x;
  const uint32_t sg = t / 16, c = t % 16, sgs = blockDim.x / 16;
  for (uint32_t trial = sg; trial < arg->trials; trial += sgs) {
    uint32_t v = in[(size_t)16 * trial + c];
    v = vx_chacha_dr_sg16(v);
    out[(size_t)16 * trial + c] = v;
  }
}
