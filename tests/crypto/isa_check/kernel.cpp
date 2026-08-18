#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include "common.h"

// One thread per (op, vector) pair, so every instruction is exercised inside a
// real warp under a real active mask rather than in isolation.

__kernel void isa_check(kernel_arg_t* __UNIFORM__ arg) {
  const uint32_t* src_a = (const uint32_t*)arg->src_a;
  const uint32_t* src_b = (const uint32_t*)arg->src_b;
  uint32_t* dst = (uint32_t*)arg->dst;

  const uint32_t stride = gridDim.x * blockDim.x;
  for (uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
       i < (uint32_t)ISA_NUM_RESULTS; i += stride) {
    const uint32_t op = i / ISA_NUM_VECTORS;
    const uint32_t v  = i % ISA_NUM_VECTORS;

    const uint32_t a = src_a[v];
    const uint32_t b = src_b[v];
    uint32_t r = 0;

    switch (op) {
    case ISA_OP_CLMUL:  r = vx_clmul(a, b);  break;
    case ISA_OP_CLMULH: r = vx_clmulh(a, b); break;
    case ISA_OP_BREV8:  r = vx_brev8(a);     break;
    case ISA_OP_AES32ESI:
      // bs is an instruction field, so it must be a compile-time constant;
      // the four values are spelled out rather than passed as a variable.
      switch (v & 3) {
      case 0:  r = vx_aes32esi(a, b, 0); break;
      case 1:  r = vx_aes32esi(a, b, 1); break;
      case 2:  r = vx_aes32esi(a, b, 2); break;
      default: r = vx_aes32esi(a, b, 3); break;
      }
      break;
    case ISA_OP_AES32ESMI:
      switch (v & 3) {
      case 0:  r = vx_aes32esmi(a, b, 0); break;
      case 1:  r = vx_aes32esmi(a, b, 1); break;
      case 2:  r = vx_aes32esmi(a, b, 2); break;
      default: r = vx_aes32esmi(a, b, 3); break;
      }
      break;
    case ISA_OP_RORI:
      // shamt is an instruction field too. The four values are the ones
      // ChaCha20 uses, addressed as rotate-right: 32-16, 32-12, 32-8, 32-7.
      switch (v & 3) {
      case 0:  r = vx_rori(a, 16); break;
      case 1:  r = vx_rori(a, 20); break;
      case 2:  r = vx_rori(a, 24); break;
      default: r = vx_rori(a, 25); break;
      }
      break;
    case ISA_OP_GHRED32L: r = vx_ghred32l(a, b); break;
    case ISA_OP_GHRED32H: r = vx_ghred32h(a, b); break;
    default: break;
    }

    dst[i] = r;
  }
}
