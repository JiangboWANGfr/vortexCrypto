#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include <crypto/vx_chacha.h>
#include "common.h"

// Exercises poly4.step.sg16 in isolation against a host-side reference.
//
// One aligned sixteen-lane subgroup handles one trial. Lane c supplies h[c] and
// r[c] for c < 5, and m[c] for every c; the instruction returns the accumulator
// after absorbing all four Poly1305 blocks, in lanes 0..4.
//
// Testing the instruction before the kernel that uses it: a 5x5 convolution
// with a wrapped reduction has a lot of places to be subtly wrong, and finding
// that in a full AEAD kernel means the tag is wrong and nothing says where.

__kernel void poly16_probe(kernel_arg_t* __UNIFORM__ arg) {
  const uint32_t* in = (const uint32_t*)arg->in;
  uint32_t* out = (uint32_t*)arg->out;
  const uint32_t t = threadIdx.x;
  const uint32_t sg = t / 16;          // which subgroup
  const uint32_t c  = t % 16;          // lane within it
  const uint32_t sgs = blockDim.x / 16;

  for (uint32_t trial = sg; trial < arg->trials; trial += sgs) {
    const uint32_t* p = in + (size_t)POLY16_IN_WORDS * trial;
    const uint32_t h = (c < 5) ? p[c]     : 0u;
    const uint32_t r = (c < 5) ? p[5 + c] : 0u;
    const uint32_t m = p[10 + c];
    const uint32_t v = vx_poly4_step_sg16(h, r, m);
    if (c < 5) {
      out[(size_t)POLY16_OUT_WORDS * trial + c] = v;
    }
  }
}
