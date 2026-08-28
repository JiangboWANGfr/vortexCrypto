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
  if (auto p = std::get_if<AuthType>(&trace->op_type)) {
    // Everything here is a single-cycle combinational datapath plus the output
    // elastic buffer, except the sixteen-lane macro-op, which runs four
    // Poly1305 block updates internally.
    //
    // These are placeholders, and the flat 2 is why: SimX does not model unit
    // busy or dispatch backpressure, so its cycle counts for the multi-cycle
    // forms are not usable and rtlsim is the authority for all of them. The
    // instruction counts, which is what SimX is relied on for, are exact.
#ifdef VX_CFG_EXT_AUTH_POLY_STEP16_ENABLE
    if (*p == AuthType::POLY_STEP16) return 21;  // 4 blocks x 5 limbs + carry
#else
    (void)p;
#endif
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

#ifdef VX_CFG_EXT_AUTH_POLY_STEP16_ENABLE
  if (auth_type == AuthType::POLY_STEP16) {
    // poly4.step.sg16 rd, rs1(h and r), rs2(m)
    //
    //   rs1 lanes 0..4 : h0..h4, five 26-bit limbs
    //   rs1 lanes 5..9 : r0..r4, the same
    //   rs2 lanes 0..15: one message word each, sixteen words = 64 bytes
    //   result         : h0'..h4' in lanes 0..4 after absorbing four Poly1305
    //                    blocks, r unchanged in 5..9, zero in 10..15
    //
    // The unit runs h = (h + m_b) * r mod 2^130-5 four times. r^2, r^3 and r^4
    // are never architectural: holding that schedule in registers is what costs
    // the software form twenty loads and a third of its cycles.
    for (uint32_t q = 0; q + 15 < num_threads; q += 16) {
      bool first = tmask.test(q);
      for (uint32_t c = 1; c < 16; ++c) {
        if (tmask.test(q + c) != first) {
          std::cerr << "error: poly4.step.sg16 on a partially active subgroup: q="
                    << q << " -- all sixteen lanes must be active" << std::endl;
          std::abort();
        }
      }
      if (!first) continue;

      uint32_t h[5], r[5], m[16];
      for (uint32_t c = 0; c < 5; ++c) {
        h[c] = (uint32_t)rs1_data[q + c].u & 0x3ffffffu;
        r[c] = (uint32_t)rs1_data[q + 5 + c].u & 0x3ffffffu;
      }
      for (uint32_t c = 0; c < 16; ++c)
        m[c] = (uint32_t)rs2_data[q + c].u;

      for (uint32_t b = 0; b < 4; ++b) {
        const uint32_t t0 = m[4*b + 0], t1 = m[4*b + 1];
        const uint32_t t2 = m[4*b + 2], t3 = m[4*b + 3];
        // Absorb, with the appended 0x01 byte a full block always carries.
        uint32_t a0 = h[0] + (t0 & 0x3ffffffu);
        uint32_t a1 = h[1] + (((t0 >> 26) | (t1 << 6)) & 0x3ffffffu);
        uint32_t a2 = h[2] + (((t1 >> 20) | (t2 << 12)) & 0x3ffffffu);
        uint32_t a3 = h[3] + (((t2 >> 14) | (t3 << 18)) & 0x3ffffffu);
        uint32_t a4 = h[4] + ((t3 >> 8) | (1u << 24));
        // Multiply by r modulo 2^130-5; the wrapped terms carry the factor 5.
        const uint64_t s1 = (uint64_t)r[1] * 5, s2 = (uint64_t)r[2] * 5;
        const uint64_t s3 = (uint64_t)r[3] * 5, s4 = (uint64_t)r[4] * 5;
        uint64_t d0 = (uint64_t)a0*r[0] + (uint64_t)a1*s4 + (uint64_t)a2*s3
                    + (uint64_t)a3*s2 + (uint64_t)a4*s1;
        uint64_t d1 = (uint64_t)a0*r[1] + (uint64_t)a1*r[0] + (uint64_t)a2*s4
                    + (uint64_t)a3*s3 + (uint64_t)a4*s2;
        uint64_t d2 = (uint64_t)a0*r[2] + (uint64_t)a1*r[1] + (uint64_t)a2*r[0]
                    + (uint64_t)a3*s4 + (uint64_t)a4*s3;
        uint64_t d3 = (uint64_t)a0*r[3] + (uint64_t)a1*r[2] + (uint64_t)a2*r[1]
                    + (uint64_t)a3*r[0] + (uint64_t)a4*s4;
        uint64_t d4 = (uint64_t)a0*r[4] + (uint64_t)a1*r[3] + (uint64_t)a2*r[2]
                    + (uint64_t)a3*r[1] + (uint64_t)a4*r[0];
        uint32_t c = (uint32_t)(d0 >> 26); h[0] = (uint32_t)d0 & 0x3ffffffu;
        d1 += c; c = (uint32_t)(d1 >> 26); h[1] = (uint32_t)d1 & 0x3ffffffu;
        d2 += c; c = (uint32_t)(d2 >> 26); h[2] = (uint32_t)d2 & 0x3ffffffu;
        d3 += c; c = (uint32_t)(d3 >> 26); h[3] = (uint32_t)d3 & 0x3ffffffu;
        d4 += c; c = (uint32_t)(d4 >> 26); h[4] = (uint32_t)d4 & 0x3ffffffu;
        h[0] += c * 5; c = h[0] >> 26; h[0] &= 0x3ffffffu;
        h[1] += c;
      }
      for (uint32_t c = 0; c < 16; ++c)
        rd_data[q + c].u = (c < 5) ? h[c]
                         : (c < 10) ? (uint32_t)rs1_data[q + c].u : 0u;
    }
    return;
  }
#endif
#ifdef VX_CFG_EXT_AUTH_POLY_SG4_ENABLE
  if (auth_type == AuthType::POLY_RSUM) {
    // Same rule as the subgroup ops in sym_unit: a quad's mask must be uniform,
    // and a masked lane contributes zero rather than a leftover limb. A wrong
    // Poly1305 tag looks exactly like a right one, so this cannot be left to
    // show up downstream.
    for (uint32_t q = 0; q + 3 < num_threads; q += 4) {
      const bool first = tmask.test(q);
      for (uint32_t c = 1; c < 4; ++c) {
        if (tmask.test(q + c) != first) {
          std::cerr << "error: poly26.rsum.sg4 on a partially active quad: q="
                    << q << " -- a quad's thread mask must be uniform" << std::endl;
          std::abort();
        }
      }
      uint32_t sum = 0;
      for (uint32_t c = 0; c < 4; ++c)
        sum += tmask.test(q + c) ? (uint32_t)rs1_data[q + c].u : 0u;
      for (uint32_t c = 0; c < 4; ++c) {
        if (tmask.test(q + c)) {
          rd_data[q + c].u = sum;
        }
      }
    }
    return;
  }
#endif

#ifdef VX_CFG_EXT_AUTH_POLY_ENABLE
  if (auth_type == AuthType::POLY_MAC) {
    auto& rs3_data = trace->src_data[2];
    auto pa = std::get<IntrAuthArgs>(trace->instr_ptr->get_args());
    const bool is_high   = (pa.sel & 0x1) != 0;
    const bool is_scale5 = (pa.sel & 0x2) != 0;
    for (uint32_t t = 0; t < num_threads; ++t) {
      if (!tmask.test(t))
        continue;
      uint64_t p = (uint64_t)(uint32_t)rs2_data[t].u
                 * (uint64_t)((uint32_t)rs3_data[t].u & 0x3ffffffu);
      if (is_scale5) {
        p += p << 2;
      }
      uint32_t part = is_high ? (uint32_t)(p >> 26)
                              : (uint32_t)(p & 0x3ffffffu);
      rd_data[t].u = (uint32_t)rs1_data[t].u + part;
    }
    return;
  }
#endif

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
          c.y[sel] ^= (uint32_t)rs1_data[t].u;
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
        uint32_t r[4];
        gf128_mul_reflected(c.y, c.h, r);
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
