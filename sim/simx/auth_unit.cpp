// Copyright © 2019-2023
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "auth_unit.h"
#include "core.h"
#include "scheduler.h"
#include "debug.h"
#include <iostream>

// The whole unit is conditional: this file is always in SRCS, but the op-type
// enums it uses only exist when the extension is enabled.
#ifdef VX_CFG_EXT_AUTH_ENABLE

using namespace vortex;

// Carry-less product of two XLEN-wide operands. Returns the full 2*XLEN result
// so CLMUL and CLMULH can select their half, mirroring the single clmul_prod
// expression in hw/rtl/crypto/auth/VX_auth_ghash.sv.
static inline void clmul_full(uint64_t a, uint64_t b, uint32_t width,
                              uint64_t* lo, uint64_t* hi) {
  uint64_t rl = 0, rh = 0;
  for (uint32_t k = 0; k < width; ++k) {
    if ((b >> k) & 1) {
      rl ^= (a << k);
      // bits shifted past the low word land in the high word; k == 0 would be
      // a shift by `width`, which is undefined behaviour, so guard it.
      if (k != 0) {
        rh ^= (a >> (width - k));
      }
    }
  }
  *lo = rl;
  *hi = rh;
}

// Reverse the bits within each byte.
static inline uint64_t brev8(uint64_t x, uint32_t width) {
  uint64_t r = 0;
  for (uint32_t j = 0; j < width / 8; ++j) {
    uint8_t byte = (uint8_t)((x >> (8 * j)) & 0xff);
    uint8_t rev = 0;
    for (uint32_t k = 0; k < 8; ++k) {
      if ((byte >> k) & 1) {
        rev |= (uint8_t)(1u << (7 - k));
      }
    }
    r |= ((uint64_t)rev << (8 * j));
  }
  return r;
}

#if defined(VX_CFG_EXT_AUTH_SG4_ENABLE) || defined(VX_CFG_EXT_AUTH_S2_ENABLE)
// Schoolbook 128x128 carry-less product in the reflected limb domain, folded
// by the R=0x87 reduction. Shared by ghmul.sg4, which spreads the operands one
// limb per lane, and by ghash.block, which holds all four limbs in one lane's
// context: the arithmetic is identical and a second copy would drift.
static void gf128_mul_reflected(const uint32_t a[4], const uint32_t b[4],
                                uint32_t r[4]) {
  auto clmul64 = [](uint32_t x, uint32_t y) -> uint64_t {
    uint64_t acc = 0;
    for (int k = 0; k < 32; ++k) {
      if ((y >> k) & 1) {
        acc ^= ((uint64_t)x) << k;
      }
    }
    return acc;
  };
  auto mul87 = [](uint32_t x) -> uint64_t {
    uint64_t e = (uint64_t)x;
    return e ^ (e << 1) ^ (e << 2) ^ (e << 7);
  };
  uint32_t p[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (uint32_t i = 0; i < 4; ++i) {
    for (uint32_t j = 0; j < 4; ++j) {
      uint64_t prod = clmul64(a[i], b[j]);
      p[i+j]   ^= (uint32_t)prod;
      p[i+j+1] ^= (uint32_t)(prod >> 32);
    }
  }
  uint64_t m4 = mul87(p[4]), m5 = mul87(p[5]);
  uint64_t m6 = mul87(p[6]), m7 = mul87(p[7]);
  uint64_t mc = mul87((uint32_t)(m7 >> 32));
  r[0] = p[0] ^ (uint32_t)m4 ^ (uint32_t)mc;
  r[1] = p[1] ^ (uint32_t)(m4 >> 32) ^ (uint32_t)m5;
  r[2] = p[2] ^ (uint32_t)(m5 >> 32) ^ (uint32_t)m6;
  r[3] = p[3] ^ (uint32_t)(m6 >> 32) ^ (uint32_t)m7;
}
#endif

AuthUnit::AuthUnit(const SimContext& ctx, const char* name, Core* core)
  : FuncUnit<VX_CFG_NUM_AUTH_BLOCKS>(ctx, name, core)
#ifdef VX_CFG_EXT_AUTH_S2_ENABLE
  , gh_ctx_((size_t)VX_CFG_NUM_WARPS * VX_CFG_NUM_THREADS)
#endif
{}

uint32_t AuthUnit::latency_of(const instr_trace_t* trace) const {
  if (std::get_if<AuthType>(&trace->op_type)) {
    // Single-cycle combinational datapath plus the output elastic buffer.
    return 2;
  }
  std::abort();
}

void AuthUnit::execute(instr_trace_t* trace) {
  auto& tmask = trace->tmask;
  uint32_t num_threads = VX_CFG_NUM_THREADS;
  auto& rs1_data = trace->src_data[0];
  auto& rs2_data = trace->src_data[1];

  trace->dst_data.assign(num_threads, reg_data_t{});
  auto& rd_data = trace->dst_data;

  auto auth_type = std::get<AuthType>(trace->op_type);
  const uint32_t width = (uint32_t)(sizeof(Word) * 8);
  const uint64_t mask = (width >= 64) ? ~0ull : ((1ull << width) - 1);

#ifdef VX_CFG_EXT_AUTH_S2_ENABLE
  if (auth_type == AuthType::GH_CWR   || auth_type == AuthType::GH_CRD
   || auth_type == AuthType::GH_INIT  || auth_type == AuthType::GH_BLOCK) {
    // Each lane runs its own message, so the thread mask is honoured here --
    // the opposite of the ghmul.sg4 rule below, which ignores it because a
    // converged quad is an architectural precondition there.
    auto authArgs = std::get<IntrAuthArgs>(trace->instr_ptr->get_args());
    const uint32_t sel = authArgs.sel & 0x7;
    for (uint32_t t = 0; t < num_threads; ++t) {
      if (!tmask.test(t))
        continue;
      auto& c = this->ctx_of(trace->wid, t);
      switch (auth_type) {
      case AuthType::GH_CWR:
        if (sel < 4) {
          c.x[sel] = (uint32_t)rs1_data[t].u;
        } else {
          c.h[sel - 4] = (uint32_t)rs1_data[t].u;
          c.h_written |= (1u << (sel - 4));
        }
        break;
      case AuthType::GH_CRD:
        rd_data[t].u = c.y[sel];
        break;
      case AuthType::GH_INIT:
        for (int i = 0; i < 4; ++i) {
          c.y[i] = 0;
        }
        break;
      case AuthType::GH_BLOCK: {
        // Same reasoning as aes.begin: an unwritten H would silently
        // authenticate under the previous kernel's subkey.
        if (c.h_written != 0xf) {
          std::cout << "error: ghash.block with an unwritten H (warp "
                    << trace->wid << ", lane " << t << ")" << std::endl;
          std::abort();
        }
        uint32_t a[4], r[4];
        for (int i = 0; i < 4; ++i) {
          a[i] = c.y[i] ^ c.x[i];
        }
        gf128_mul_reflected(a, c.h, r);
        for (int i = 0; i < 4; ++i) {
          c.y[i] = r[i];
        }
      } break;
      default:
        break;
      }
    }
    return;
  }
#endif

#ifdef VX_CFG_EXT_AUTH_SG4_ENABLE
  if (auth_type == AuthType::GHMUL_SG4) {
    // The quad's rs1 and rs2 are one 128-bit value each, a limb per lane. The
    // schoolbook product and the fold are the same arithmetic the software
    // ghash_mul_hw does, in the same reflected limb domain, so the kernel's
    // brev8 conventions are unchanged. The source lane's mask is deliberately
    // not consulted: the instruction requires a converged quad, and this is the
    // rule the RTL implements.
    for (uint32_t q = 0; q + 3 < num_threads; q += 4) {
      if (!tmask.test(q) && !tmask.test(q+1) && !tmask.test(q+2) && !tmask.test(q+3))
        continue;
      uint32_t a[4], b[4], r[4];
      for (uint32_t i = 0; i < 4; ++i) {
        a[i] = (uint32_t)rs1_data[q+i].u;
        b[i] = (uint32_t)rs2_data[q+i].u;
      }
      gf128_mul_reflected(a, b, r);
      for (uint32_t c = 0; c < 4; ++c) {
        if (tmask.test(q + c)) {
          rd_data[q + c].u = r[c];
        }
      }
    }
    return;
  }
#endif

  for (uint32_t t = 0; t < num_threads; ++t) {
    if (!tmask.test(t))
      continue;
    uint64_t a = (uint64_t)rs1_data[t].u & mask;
    uint64_t b = (uint64_t)rs2_data[t].u & mask;
    uint64_t res;
    switch (auth_type) {
    case AuthType::BREV8:
      res = brev8(a, width);
      break;
    case AuthType::GHRED32L:
    case AuthType::GHRED32H: {
      // 0x87 is the GF(2^128) reduction constant; carry-less multiply by it is
      // x ^ (x<<1) ^ (x<<2) ^ (x<<7). Must match VX_auth_ghash.sv bit for bit.
      //
      // The halves are accumulated separately rather than as one shifted value:
      // the product is width+7 bits, so at width 64 it does not fit a uint64_t,
      // and `p >> width` would have been shift-by-64 -- undefined behaviour that
      // gcc folds to 0. Each shift here is by less than width.
      uint64_t plo = 0, phi = 0;
      for (uint32_t k : {0u, 1u, 2u, 7u}) {
        plo ^= (b << k);
        if (k != 0) {
          phi ^= (b >> (width - k));
        }
      }
      res = a ^ ((auth_type == AuthType::GHRED32H) ? phi : plo);
      break;
    }
    case AuthType::CLMUL:
    case AuthType::CLMULH: {
      uint64_t lo, hi;
      clmul_full(a, b, width, &lo, &hi);
      res = (auth_type == AuthType::CLMULH) ? hi : lo;
      break;
    }
    default:
      std::abort();
    }
    rd_data[t].u = res & mask;
  }
}

void AuthUnit::on_tick() {
  for (uint32_t b = 0; b < VX_CFG_NUM_AUTH_BLOCKS; ++b) {
    auto& input = Inputs.at(b);
    if (input.empty())
      continue;
    auto& output = Outputs.at(b);
    if (output.full())
      continue; // stall
    auto trace = input.peek();
    this->execute(trace);
    uint32_t delay = this->latency_of(trace);
    output.send(trace, delay);
    input.pop();
  }
}

#endif // VX_CFG_EXT_AUTH_ENABLE
