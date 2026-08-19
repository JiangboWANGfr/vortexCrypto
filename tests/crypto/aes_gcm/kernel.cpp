#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include "common.h"

// One CTA per core, one independent AES-128-GCM message per thread.
// The key schedule, the four T-tables and the GHASH table are copied into
// local memory once by the whole CTA and then read by every thread. That
// placement is the point of the baseline: a table lookup is a data-dependent
// gather across the SIMD width, and local memory banks as wide as the warp
// while the L1 data cache is single-banked.

namespace {

struct lmem_layout_t {
  uint32_t te[AES_TE_TABLES * AES_TE_ENTRIES];
  uint32_t rk[AES128_RK_BYTES / 4];
  uint8_t htable[GHASH_TABLE_BYTES];
};

inline uint32_t load_be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
       | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

inline void store_be32(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

// T-table AES-128 encryption of one block, state held as four big-endian
// column words.
//
// PERM selects the order in which the four column words of a round are
// computed. They are independent -- each reads s0..s3 and the round key and
// writes only its own temporary -- so reversing them is bit-identical by
// construction rather than merely equivalent. PERM == 1 is the floor probe;
// see aes_gcm_sw_ttable_perm below.
template <int PERM>
inline void aes128_encrypt(const lmem_layout_t* lm, const uint8_t in[16],
                           uint8_t out[16]) {
  const uint32_t* te0 = lm->te;
  const uint32_t* te1 = lm->te + AES_TE_ENTRIES;
  const uint32_t* te2 = lm->te + 2 * AES_TE_ENTRIES;
  const uint32_t* te3 = lm->te + 3 * AES_TE_ENTRIES;
  const uint32_t* rk = lm->rk;

  uint32_t s0 = load_be32(in) ^ rk[0];
  uint32_t s1 = load_be32(in + 4) ^ rk[1];
  uint32_t s2 = load_be32(in + 8) ^ rk[2];
  uint32_t s3 = load_be32(in + 12) ^ rk[3];

  for (int round = 1; round < AES128_ROUNDS; ++round) {
    const uint32_t* k = rk + 4 * round;
    uint32_t t0, t1, t2, t3;
    if (PERM == 1) {
      t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff]
         ^ te2[(s1 >> 8) & 0xff] ^ te3[s2 & 0xff] ^ k[3];
      t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff]
         ^ te2[(s0 >> 8) & 0xff] ^ te3[s1 & 0xff] ^ k[2];
      t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff]
         ^ te2[(s3 >> 8) & 0xff] ^ te3[s0 & 0xff] ^ k[1];
      t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff]
         ^ te2[(s2 >> 8) & 0xff] ^ te3[s3 & 0xff] ^ k[0];
    } else {
      t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff]
         ^ te2[(s2 >> 8) & 0xff] ^ te3[s3 & 0xff] ^ k[0];
      t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff]
         ^ te2[(s3 >> 8) & 0xff] ^ te3[s0 & 0xff] ^ k[1];
      t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff]
         ^ te2[(s0 >> 8) & 0xff] ^ te3[s1 & 0xff] ^ k[2];
      t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff]
         ^ te2[(s1 >> 8) & 0xff] ^ te3[s2 & 0xff] ^ k[3];
    }
    s0 = t0; s1 = t1; s2 = t2; s3 = t3;
  }

  // The last round drops MixColumns, so take the plain S-box out of Te0.
  const uint32_t* k = rk + 4 * AES128_ROUNDS;
  const uint32_t f0 = (((te0[s0 >> 24] >> 16) & 0xff) << 24)
                    | (((te0[(s1 >> 16) & 0xff] >> 16) & 0xff) << 16)
                    | (((te0[(s2 >> 8) & 0xff] >> 16) & 0xff) << 8)
                    | ((te0[s3 & 0xff] >> 16) & 0xff);
  const uint32_t f1 = (((te0[s1 >> 24] >> 16) & 0xff) << 24)
                    | (((te0[(s2 >> 16) & 0xff] >> 16) & 0xff) << 16)
                    | (((te0[(s3 >> 8) & 0xff] >> 16) & 0xff) << 8)
                    | ((te0[s0 & 0xff] >> 16) & 0xff);
  const uint32_t f2 = (((te0[s2 >> 24] >> 16) & 0xff) << 24)
                    | (((te0[(s3 >> 16) & 0xff] >> 16) & 0xff) << 16)
                    | (((te0[(s0 >> 8) & 0xff] >> 16) & 0xff) << 8)
                    | ((te0[s1 & 0xff] >> 16) & 0xff);
  const uint32_t f3 = (((te0[s3 >> 24] >> 16) & 0xff) << 24)
                    | (((te0[(s0 >> 16) & 0xff] >> 16) & 0xff) << 16)
                    | (((te0[(s1 >> 8) & 0xff] >> 16) & 0xff) << 8)
                    | ((te0[s2 & 0xff] >> 16) & 0xff);

  store_be32(out, f0 ^ k[0]);
  store_be32(out + 4, f1 ^ k[1]);
  store_be32(out + 8, f2 ^ k[2]);
  store_be32(out + 12, f3 ^ k[3]);
}

// Y = Y * H over GF(2^128), four bits of Y per step against the precomputed
// table. Reduction constants for a four-bit shift, SP 800-38D section 6.3.
static const uint16_t kRem4[16] = {
  0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
  0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
};

inline void ghash_mul(const uint8_t* htable, uint8_t y[16]) {
  // Y*H = sum over nibbles k of x^(4k) * (nibble_k * H), evaluated by Horner
  // from the highest k down, so the loop walks the last nibble first.
  uint8_t z[16] = {0};
  for (int i = 31; i >= 0; --i) {
    const uint8_t byte = y[i >> 1];
    const uint8_t nib = (i & 1) ? (uint8_t)(byte & 0x0f) : (uint8_t)(byte >> 4);
    if (i != 31) {
      // z >>= 4, folding the four bits that fall off back in.
      const uint8_t low = (uint8_t)(z[15] & 0x0f);
      for (int j = 15; j > 0; --j) {
        z[j] = (uint8_t)((z[j] >> 4) | (z[j - 1] << 4));
      }
      z[0] >>= 4;
      const uint16_t rem = kRem4[low];
      z[0] ^= (uint8_t)(rem >> 8);
      z[1] ^= (uint8_t)rem;
    }
    const uint8_t* h = htable + 16 * nib;
    for (int j = 0; j < 16; ++j) {
      z[j] ^= h[j];
    }
  }
  for (int j = 0; j < 16; ++j) {
    y[j] = z[j];
  }
}

inline void inc32(uint8_t ctr[16]) {
  for (int i = 15; i >= 12; --i) {
    if (++ctr[i] != 0) {
      break;
    }
  }
}

} // namespace

namespace {

// The software baseline, parameterised on the floor probe's permutation so the
// two entry points below are the same source with one ordering difference.
template <int PERM>
inline void aes_gcm_sw_body(kernel_arg_t* __UNIFORM__ arg) {
  lmem_layout_t* lm = (lmem_layout_t*)__local_mem();

  // Cooperative fill: the CTA spans every warp on the core, so the tables
  // must be filled by all of them and fenced before any thread reads them.
  {
    const uint32_t* te_src = (const uint32_t*)arg->te_addr;
    const uint32_t* rk_src = (const uint32_t*)arg->rk_addr;
    const uint32_t* ht_src = (const uint32_t*)arg->htable_addr;
    const uint32_t tid = threadIdx.x;
    const uint32_t nthreads = blockDim.x;
    for (uint32_t i = tid; i < AES_TE_TABLES * AES_TE_ENTRIES; i += nthreads) {
      lm->te[i] = te_src[i];
    }
    for (uint32_t i = tid; i < AES128_RK_BYTES / 4; i += nthreads) {
      lm->rk[i] = rk_src[i];
    }
    uint32_t* ht_dst = (uint32_t*)lm->htable;
    for (uint32_t i = tid; i < GHASH_TABLE_BYTES / 4; i += nthreads) {
      ht_dst[i] = ht_src[i];
    }
  }
  __syncthreads();

  const uint32_t num_msgs = arg->num_msgs;
  const uint32_t blocks = arg->blocks_per_msg;
  const uint32_t tail = arg->tail_bytes;
  const uint32_t aad_bytes = arg->aad_bytes;
  const uint8_t* aad = (const uint8_t*)arg->aad_addr;
  const uint32_t msg_bytes = 16u * blocks + tail;
  const uint32_t msg_stride = 16u * (blocks + (tail != 0u ? 1u : 0u));
  const uint8_t* iv_base = (const uint8_t*)arg->iv_addr;
  const uint8_t* src_base = (const uint8_t*)arg->src_addr;
  uint8_t* dst_base = (uint8_t*)arg->dst_addr;
  uint8_t* tag_base = (uint8_t*)arg->tag_addr;

  const uint32_t stride = gridDim.x * blockDim.x;
  for (uint32_t msg = blockIdx.x * blockDim.x + threadIdx.x; msg < num_msgs;
       msg += stride) {
    uint8_t j0[16];
    const uint8_t* iv = iv_base + GCM_IV_BYTES * msg;
    for (int i = 0; i < GCM_IV_BYTES; ++i) {
      j0[i] = iv[i];
    }
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;

    uint8_t ctr[16];
    for (int i = 0; i < 16; ++i) {
      ctr[i] = j0[i];
    }

    uint8_t y[16] = {0};

    // AAD, absorbed before any ciphertext and never encrypted.
    for (uint32_t off = 0; off < aad_bytes; off += 16) {
      const uint32_t n = (aad_bytes - off < 16u) ? (aad_bytes - off) : 16u;
      for (uint32_t i = 0; i < n; ++i) {
        y[i] ^= aad[off + i];
      }
      ghash_mul(lm->htable, y);
    }

    const uint8_t* pt = src_base + (size_t)msg_stride * msg;
    uint8_t* ct = dst_base + (size_t)msg_stride * msg;
    for (uint32_t b = 0; b < blocks; ++b) {
      inc32(ctr);
      uint8_t ks[16];
      aes128_encrypt<PERM>(lm, ctr, ks);
      for (int i = 0; i < 16; ++i) {
        const uint8_t c = (uint8_t)(pt[16 * b + i] ^ ks[i]);
        ct[16 * b + i] = c;
        y[i] ^= c;
      }
      ghash_mul(lm->htable, y);
    }

    // Partial final block, SP 800-38D 7.1 step 4: `tail` bytes of keystream
    // consumed, ciphertext fragment zero-padded before GHASH absorbs it.
    if (tail != 0) {
      inc32(ctr);
      uint8_t ks[16];
      aes128_encrypt<PERM>(lm, ctr, ks);
      for (uint32_t i = 0; i < tail; ++i) {
        const uint8_t c = (uint8_t)(pt[16 * blocks + i] ^ ks[i]);
        ct[16 * blocks + i] = c;
        y[i] ^= c;
      }
      ghash_mul(lm->htable, y);
    }

    const uint64_t abits = (uint64_t)aad_bytes * 8u;
    const uint64_t cbits = (uint64_t)msg_bytes * 8u;
    for (int i = 0; i < 8; ++i) {
      y[7 - i] ^= (uint8_t)(abits >> (8 * i));
      y[15 - i] ^= (uint8_t)(cbits >> (8 * i));
    }
    ghash_mul(lm->htable, y);

    uint8_t ej0[16];
    aes128_encrypt<PERM>(lm, j0, ej0);
    uint8_t* tag = tag_base + GCM_TAG_BYTES * msg;
    for (int i = 0; i < 16; ++i) {
      tag[i] = (uint8_t)(y[i] ^ ej0[i]);
    }
  }
}

} // namespace

__kernel void aes_gcm_sw_ttable(kernel_arg_t* __UNIFORM__ arg) {
  aes_gcm_sw_body<0>(arg);
}

// Bit-identical to aes_gcm_sw_ttable, and the only thing it measures is the
// distance between two kernels that cannot differ -- the floor below which a
// cycle result from the SOFTWARE kernel is not legible. It exists because the
// probe this application already had reverses statements inside ghash_mul_hw,
// which this kernel never calls: it read 0.00%, byte-identical, and bounded
// nothing.
//
// The probe has a validity condition and it must be checked on every use: the
// two entry points must differ by a SMALL FIXED number of instructions that
// does not grow with the block count. Absolute, not proportional -- a valid
// probe perturbs the count by a constant, so a percentage threshold rejects it
// at small problem sizes and accepts a scaling perturbation at large ones. A
// probe that fails this silently is worse than no probe, because it fails
// toward ending the inquiry; see the rejected probes in
// tests/crypto/chacha_poly/kernel.cpp for what that looks like.
//
// Measured at c2w4t16, -n128, blocks 16/32/64: the counts are EQUAL, not merely
// fixed -- 649,078 / 1,257,462 / 2,474,230 on both entry points -- and the cycle
// distance is 0.16% to 0.47%. See section 16.2 of the proposal.
__kernel void aes_gcm_sw_ttable_perm(kernel_arg_t* __UNIFORM__ arg) {
  aes_gcm_sw_body<1>(arg);
}

// ---------------------------------------------------------------------------
// Hardware variant: EX_SYM (aes32esmi/aes32esi) + EX_AUTH (clmul/clmulh/brev8)
//
// Both tables the software baseline needs disappear here. AES becomes register
// arithmetic instead of four 1 KB T-table gathers, and GHASH becomes a
// carry-less multiply instead of a 256-byte nibble table walked 32 times. The
// only thing left in local memory is the key schedule, which both variants
// read the same way, so the comparison is not distorted by one of them keeping
// a table resident and the other not.
//
// Two byte-order conventions have to be right, and getting either wrong is
// silent:
//
//  - aes32* selects byte `bs` as (rs2 >> 8*bs), so an AES state word must be
//    LITTLE-endian packed (row r at bit 8r). The shared round keys are
//    big-endian packed (aes_gcm_ref::rk_to_words), so they are byte-swapped
//    once per CTA during the local-memory fill rather than per use.
//  - GCM numbers the bits of each byte in the opposite order to the polynomial
//    convention clmul assumes: coefficient of x^i is bit (7 - i%8) of byte i/8.
//    A little-endian word load puts that at bit 8*(i/8) + 7 - i%8, so brev8
//    alone moves it to bit i. Limb order is already correct, so there is no
//    128-bit reversal and no shift-by-1 correction of the kind a whole-value
//    reflection would need.

namespace {

inline uint32_t bswap32(uint32_t v) {
  return (v >> 24) | ((v >> 8) & 0x0000ff00u)
       | ((v << 8) & 0x00ff0000u) | (v << 24);
}

inline uint32_t load_le32(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
       | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

inline void store_le32(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

struct hw_lmem_layout_t {
  uint32_t rk[AES128_RK_BYTES / 4];   // little-endian packed
};

// AES-128 block encryption. State words are little-endian packed columns;
// ShiftRows is expressed by which state word each byte-select reads from.
// always_inline, not inline. LLVM declined to inline these two at -O3 (they are
// large and have several call sites), and because they take array pointers that
// forced ctr[], ks[], y[] and h[] into stack slots. On this machine that is the
// worst possible placement: vx_start.S gives each hart a stack 8 KB apart, so a
// single sp-relative access in a warp becomes NUM_THREADS distinct cache lines
// 8 KB apart -- a fully divergent gather on a single-banked L1, replayed at warp
// width. Inlining keeps all four arrays in registers and deletes that traffic.
__attribute__((always_inline))
inline void aes128_encrypt_hw(const uint32_t* rk, const uint32_t in[4],
                              uint32_t out[4]) {
  uint32_t s0 = in[0] ^ rk[0];
  uint32_t s1 = in[1] ^ rk[1];
  uint32_t s2 = in[2] ^ rk[2];
  uint32_t s3 = in[3] ^ rk[3];

  for (int round = 1; round < AES128_ROUNDS; ++round) {
    const uint32_t* k = rk + 4 * round;
    uint32_t t0 = k[0], t1 = k[1], t2 = k[2], t3 = k[3];
    t0 = vx_aes32esmi(t0, s0, 0); t0 = vx_aes32esmi(t0, s1, 1);
    t0 = vx_aes32esmi(t0, s2, 2); t0 = vx_aes32esmi(t0, s3, 3);
    t1 = vx_aes32esmi(t1, s1, 0); t1 = vx_aes32esmi(t1, s2, 1);
    t1 = vx_aes32esmi(t1, s3, 2); t1 = vx_aes32esmi(t1, s0, 3);
    t2 = vx_aes32esmi(t2, s2, 0); t2 = vx_aes32esmi(t2, s3, 1);
    t2 = vx_aes32esmi(t2, s0, 2); t2 = vx_aes32esmi(t2, s1, 3);
    t3 = vx_aes32esmi(t3, s3, 0); t3 = vx_aes32esmi(t3, s0, 1);
    t3 = vx_aes32esmi(t3, s1, 2); t3 = vx_aes32esmi(t3, s2, 3);
    s0 = t0; s1 = t1; s2 = t2; s3 = t3;
  }

  // Final round: no MixColumns.
  const uint32_t* k = rk + 4 * AES128_ROUNDS;
  uint32_t t0 = k[0], t1 = k[1], t2 = k[2], t3 = k[3];
  t0 = vx_aes32esi(t0, s0, 0); t0 = vx_aes32esi(t0, s1, 1);
  t0 = vx_aes32esi(t0, s2, 2); t0 = vx_aes32esi(t0, s3, 3);
  t1 = vx_aes32esi(t1, s1, 0); t1 = vx_aes32esi(t1, s2, 1);
  t1 = vx_aes32esi(t1, s3, 2); t1 = vx_aes32esi(t1, s0, 3);
  t2 = vx_aes32esi(t2, s2, 0); t2 = vx_aes32esi(t2, s3, 1);
  t2 = vx_aes32esi(t2, s0, 2); t2 = vx_aes32esi(t2, s1, 3);
  t3 = vx_aes32esi(t3, s3, 0); t3 = vx_aes32esi(t3, s0, 1);
  t3 = vx_aes32esi(t3, s1, 2); t3 = vx_aes32esi(t3, s2, 3);
  out[0] = t0; out[1] = t1; out[2] = t2; out[3] = t3;
}

// SUBGROUP-COOPERATIVE (S3) FORM OF THE SAME BLOCK ENCRYPTION -- A PROBE.
//
// Lane c of each aligned group of four holds AES state column c, so the four
// columns of one block live in four lanes instead of four registers of one
// lane. ShiftRows is then a lane rotation rather than a choice of register:
// aes32esmi's byte-step `bs` makes output column j consume state column
// (j + bs) & 3 (see the lane-local form above, where t0 reads s0,s1,s2,s3 and
// t1 reads s1,s2,s3,s0), so at step p lane c must read lane (c + p) & 3 of the
// same aligned quad.
//
// Nothing here is new hardware. `vx_shfl_idx` is decoded in every build --
// custom0, funct7=0x01, funct3=7, not behind any enable -- and resolves the
// source as `lane = (i & mask) | (bval & ~mask)` guarded by
// `lane <= (i & mask) | (cval & ~mask)`. With mask = 0x3c, cval = 3 and a
// PER-LANE bval = (c + p) & 3 that is exactly the aligned rotate. bval must be
// per-lane: a compile-time constant there makes every lane of the quad read the
// same source, which is a broadcast and computes the wrong cipher.
//
// mask = 0x3c is the width-portable spelling. The RTL slices LANE_BITS from bit
// 12 (VX_alu_int.sv:184) so it truncates to 0xc at 16 threads and 0x1c at 32,
// while simx keeps six bits (alu_unit.cpp:279); `bval & ~mask` preserves bits
// 0-1 in every case, and at 4 threads the mask degenerates to 0 with the whole
// warp as one quad, which is still the same rotate.
//
// The quad must be converged: all four lanes are read by every rotate, and the
// two models disagree about a masked source lane (RTL falls back to the reading
// lane, simx does not). main.cpp refuses a message count that is not a multiple
// of four, which is what keeps every quad whole here.
__attribute__((always_inline))
inline uint32_t aes128_encrypt_sg4(const uint32_t* rk, uint32_t c,
                                   uint32_t b1, uint32_t b2, uint32_t b3,
                                   uint32_t in_col) {
  uint32_t s = in_col ^ rk[c];

  for (int round = 1; round < AES128_ROUNDS; ++round) {
    const uint32_t s1 = (uint32_t)vx_shfl_idx(s, (int)b1, 3, 0x3c);
    const uint32_t s2 = (uint32_t)vx_shfl_idx(s, (int)b2, 3, 0x3c);
    const uint32_t s3 = (uint32_t)vx_shfl_idx(s, (int)b3, 3, 0x3c);
    uint32_t t = rk[4 * round + c];
    t = vx_aes32esmi(t, s,  0);
    t = vx_aes32esmi(t, s1, 1);
    t = vx_aes32esmi(t, s2, 2);
    t = vx_aes32esmi(t, s3, 3);
    s = t;
  }

  const uint32_t s1 = (uint32_t)vx_shfl_idx(s, (int)b1, 3, 0x3c);
  const uint32_t s2 = (uint32_t)vx_shfl_idx(s, (int)b2, 3, 0x3c);
  const uint32_t s3 = (uint32_t)vx_shfl_idx(s, (int)b3, 3, 0x3c);
  uint32_t t = rk[4 * AES128_ROUNDS + c];
  t = vx_aes32esi(t, s,  0);
  t = vx_aes32esi(t, s1, 1);
  t = vx_aes32esi(t, s2, 2);
  t = vx_aes32esi(t, s3, 3);
  return t;
}

// y = y * h over GF(2^128) mod x^128 + x^7 + x^2 + x + 1, both in the
// reflected limb domain. Schoolbook 4x4; Karatsuba trades 14 clmul for 11 xor
// here, which is a wash at this width and is not worth the complexity until
// clmul is measured to be more expensive than an xor.
__attribute__((always_inline))
inline void ghash_mul_hw(const uint32_t h[4], uint32_t y[4]) {
  uint32_t p[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      p[i + j]     ^= vx_clmul(y[i], h[j]);
      p[i + j + 1] ^= vx_clmulh(y[i], h[j]);
    }
  }

  // Fold the high 128 bits down: x^128 == 0x87. Each limb times 0x87 is 39
  // bits, so it needs both halves. The final carry out of limb 3 is at most 7
  // bits, so folding it once more lands wholly inside limb 0 and terminates.
  const uint32_t R = 0x87;
  uint32_t r0 = p[0], r1 = p[1], r2 = p[2], r3 = p[3];
  r0 ^= vx_clmul(p[4], R);
  r1 ^= vx_clmulh(p[4], R) ^ vx_clmul(p[5], R);
  r2 ^= vx_clmulh(p[5], R) ^ vx_clmul(p[6], R);
  r3 ^= vx_clmulh(p[6], R) ^ vx_clmul(p[7], R);
  const uint32_t c = vx_clmulh(p[7], R);
  r0 ^= vx_clmul(c, R);

  y[0] = r0; y[1] = r1; y[2] = r2; y[3] = r3;
}

// The keystream generator the message loop below uses. KS_LANE_LOCAL is the
// shipped S1 form -- one lane computes a whole block. KS_SUBGROUP_4 is the S3
// probe: four lanes cooperate on one block, and the group round-robins over the
// four messages it owns so that the payload, the GHASH half and the number of
// messages in flight per warp are all left exactly as they are. The only thing
// that differs between the two instantiations is where the keystream comes
// from, which is what makes the difference between them attributable.
enum { KS_LANE_LOCAL = 0, KS_SUBGROUP_4 = 1 };

// Where block b of message m lives. LAYOUT_CONTIG is the shipped arrangement:
// each message is one contiguous run, so one warp-load touches NUM_LANES lines
// msg_stride apart. LAYOUT_INTERLEAVED puts block b of every message together,
// so the same warp-load touches NUM_LANES consecutive 16-byte blocks -- four
// lines instead of sixteen at 16 lanes.
//
// This is a DIAGNOSTIC, not a proposal: a server handling independent records
// does not get to choose that layout. It exists to put a ceiling on what any
// scheme that improves payload locality -- including a subgroup mapping that
// gives four lanes to one block -- could be worth, without building one.
// LAYOUT_CONTIG_OFS is the SAME layout as LAYOUT_CONTIG, addressed as
// base-plus-offset instead of a pointer walk. Semantically identical; it is
// kept as a specimen because it costs 20.6% (section 18.2) and that number is
// the largest unexplained movement recorded in this project.
enum { LAYOUT_CONTIG = 0, LAYOUT_INTERLEAVED = 1, LAYOUT_CONTIG_OFS = 2 };

template <int KS, int LAYOUT = LAYOUT_CONTIG>
inline void aes_gcm_hw_body(kernel_arg_t* __UNIFORM__ arg) {
  hw_lmem_layout_t* lm = (hw_lmem_layout_t*)__local_mem();

  {
    const uint32_t* rk_src = (const uint32_t*)arg->rk_addr;
    const uint32_t tid = threadIdx.x;
    const uint32_t nthreads = blockDim.x;
    for (uint32_t i = tid; i < AES128_RK_BYTES / 4; i += nthreads) {
      lm->rk[i] = bswap32(rk_src[i]);
    }
  }
  __syncthreads();

  // Lane position inside the aligned quad, and the three rotate descriptors it
  // needs. Loop-invariant, so they are computed once here rather than per round.
  const uint32_t sg4_c  = (uint32_t)(vx_thread_id() & 3);
  const uint32_t sg4_b1 = (sg4_c + 1u) & 3u;
  const uint32_t sg4_b2 = (sg4_c + 2u) & 3u;
  const uint32_t sg4_b3 = (sg4_c + 3u) & 3u;

  // Reflect H once per thread; it is loop-invariant across every block.
  uint32_t h[4];
  {
    const uint8_t* hp = (const uint8_t*)arg->h_addr;
    for (int i = 0; i < 4; ++i) {
      h[i] = vx_brev8(load_le32(hp + 4 * i));
    }
  }

  const uint32_t num_msgs = arg->num_msgs;
  const uint32_t blocks = arg->blocks_per_msg;
  const uint32_t tail = arg->tail_bytes;
  const uint32_t aad_bytes = arg->aad_bytes;
  const uint8_t* aad = (const uint8_t*)arg->aad_addr;
  const uint32_t msg_bytes = 16u * blocks + tail;
  // Buffer stride is the message length rounded UP to a whole block, and is
  // deliberately not the message length. The word-wise streaming path below is
  // only valid while each message base is 4-byte aligned; a byte-granular
  // stride breaks that the moment a tail makes it odd, and RISC-V traps on the
  // unaligned word access rather than fixing it up. The padding bytes are never
  // read and never authenticated -- msg_bytes is what GCM sees.
  const uint32_t msg_stride = 16u * (blocks + (tail != 0u ? 1u : 0u));
  const uint8_t* iv_base = (const uint8_t*)arg->iv_addr;
  const uint8_t* src_base = (const uint8_t*)arg->src_addr;
  uint8_t* dst_base = (uint8_t*)arg->dst_addr;
  uint8_t* tag_base = (uint8_t*)arg->tag_addr;

  const uint32_t stride = gridDim.x * blockDim.x;
  for (uint32_t msg = blockIdx.x * blockDim.x + threadIdx.x; msg < num_msgs;
       msg += stride) {
    const uint8_t* iv = iv_base + GCM_IV_BYTES * msg;
    uint32_t j0[4];
    j0[0] = load_le32(iv);
    j0[1] = load_le32(iv + 4);
    j0[2] = load_le32(iv + 8);
    j0[3] = 0x01000000u;   // big-endian 1 in the counter position

    uint32_t ctr[4] = {j0[0], j0[1], j0[2], j0[3]};
    uint32_t y[4] = {0, 0, 0, 0};

    // AAD first, and it is not encrypted (SP 800-38D 7.1 step 5). Byte-wise
    // because the AAD length is arbitrary and its base carries no alignment
    // guarantee; it runs once per message, not once per block, so the word-wise
    // path is not worth the precondition it would impose.
    for (uint32_t off = 0; off < aad_bytes; off += 16) {
      const uint32_t n = (aad_bytes - off < 16u) ? (aad_bytes - off) : 16u;
      uint8_t padded[16] = {0};
      for (uint32_t i = 0; i < n; ++i) {
        padded[i] = aad[off + i];
      }
      for (int i = 0; i < 4; ++i) {
        y[i] ^= vx_brev8(load_le32(padded + 4 * i));
      }
      ghash_mul_hw(h, y);
    }

    const uint8_t* pt = src_base + (size_t)msg_stride * msg;
    uint8_t* ct = dst_base + (size_t)msg_stride * msg;

    for (uint32_t b = 0; b < blocks; ++b) {
      // inc32 on the trailing big-endian counter word
      ctr[3] = bswap32(bswap32(ctr[3]) + 1);

      uint32_t ks[4];
      if (KS == KS_SUBGROUP_4) {
        // Distribute: after the transpose lane i holds column i of the counter
        // belonging to message p of this quad, for p = 0..3.
        uint32_t q0, q1, q2, q3;
        vx_transpose4(ctr[0], ctr[1], ctr[2], ctr[3], q0, q1, q2, q3);
        // Four cooperative passes, one per message the quad owns.
        const uint32_t r0 = aes128_encrypt_sg4(lm->rk, sg4_c, sg4_b1, sg4_b2, sg4_b3, q0);
        const uint32_t r1 = aes128_encrypt_sg4(lm->rk, sg4_c, sg4_b1, sg4_b2, sg4_b3, q1);
        const uint32_t r2 = aes128_encrypt_sg4(lm->rk, sg4_c, sg4_b1, sg4_b2, sg4_b3, q2);
        const uint32_t r3 = aes128_encrypt_sg4(lm->rk, sg4_c, sg4_b1, sg4_b2, sg4_b3, q3);
        // Collect: the transpose is its own inverse, so each lane gets its own
        // message's four keystream words back and the rest of the loop is
        // unchanged.
        vx_transpose4(r0, r1, r2, r3, ks[0], ks[1], ks[2], ks[3]);
      } else {
        aes128_encrypt_hw(lm->rk, ctr, ks);
      }

      // Word-wise, not via load_le32/store_le32: those are byte-at-a-time, and
      // RISC-V's strict-alignment default stops LLVM widening them, costing 16
      // lbu + 16 sb per block instead of 4 + 4. The buffers are vx_mem_alloc'd
      // and indexed at 16-byte granularity, so word access is aligned.
      // The contiguous arm must stay byte-identical to what it was before the
      // layout parameter existed: rewriting it as an offset from src_base cost
      // hw_s1 1,504 instructions and 20.6% of its cycles, which is four times
      // this kernel's floor. The diagnostic arm may compute what it likes.
      const uint32_t* pt_w;
      uint32_t* ct_w;
      if (LAYOUT == LAYOUT_INTERLEAVED) {
        const size_t blk = (size_t)16 * ((size_t)b * num_msgs + msg);
        pt_w = (const uint32_t*)(src_base + blk);
        ct_w = (uint32_t*)(dst_base + blk);
      } else if (LAYOUT == LAYOUT_CONTIG_OFS) {
        const size_t blk = (size_t)msg_stride * msg + (size_t)16 * b;
        pt_w = (const uint32_t*)(src_base + blk);
        ct_w = (uint32_t*)(dst_base + blk);
      } else {
        pt_w = (const uint32_t*)(pt + 16 * b);
        ct_w = (uint32_t*)(ct + 16 * b);
      }
      for (int i = 0; i < 4; ++i) {
        const uint32_t c = pt_w[i] ^ ks[i];
        ct_w[i] = c;
        y[i] ^= vx_brev8(c);
      }
      ghash_mul_hw(h, y);
    }

    // Partial final block, SP 800-38D section 7.1 step 4. Only `tail` bytes of
    // keystream are consumed and the ciphertext fragment is zero-padded to a
    // full block before GHASH absorbs it -- padding with the surrounding
    // plaintext instead would change the tag. Byte-wise on purpose: the
    // word-wise fast path above is justified by 16-byte alignment, which a tail
    // by definition does not have, and a word store here would write up to 15
    // bytes past the caller's buffer.
    if (tail != 0) {
      ctr[3] = bswap32(bswap32(ctr[3]) + 1);
      uint32_t ks[4];
      aes128_encrypt_hw(lm->rk, ctr, ks);
      uint8_t padded[16] = {0};
      for (uint32_t i = 0; i < tail; ++i) {
        const uint8_t k = (uint8_t)(ks[i >> 2] >> (8 * (i & 3)));
        const uint8_t c = (uint8_t)(pt[16 * blocks + i] ^ k);
        ct[16 * blocks + i] = c;
        padded[i] = c;
      }
      for (int i = 0; i < 4; ++i) {
        y[i] ^= vx_brev8(load_le32(padded + 4 * i));
      }
      ghash_mul_hw(h, y);
    }

    // Length block: [len(A)]64 || [len(C)]64, big-endian, so the two 32-bit
    // halves land byte-swapped in the little-endian limbs before reflection.
    const uint64_t abits = (uint64_t)aad_bytes * 8u;
    const uint64_t cbits = (uint64_t)msg_bytes * 8u;
    y[0] ^= vx_brev8(bswap32((uint32_t)(abits >> 32)));
    y[1] ^= vx_brev8(bswap32((uint32_t)abits));
    y[2] ^= vx_brev8(bswap32((uint32_t)(cbits >> 32)));
    y[3] ^= vx_brev8(bswap32((uint32_t)cbits));
    ghash_mul_hw(h, y);

    uint32_t ej0[4];
    aes128_encrypt_hw(lm->rk, j0, ej0);
    uint8_t* tag = tag_base + GCM_TAG_BYTES * msg;
    for (int i = 0; i < 4; ++i) {
      store_le32(tag + 4 * i, vx_brev8(y[i]) ^ ej0[i]);
    }
  }
}


// ---------------------------------------------------------------------------
// TRUE S3: a quad of four lanes owns ONE message from the counter to the tag.
//
// Nothing is ever collected back into a single lane. Lane c of each aligned quad
// holds, throughout: counter word c, AES state column c, ciphertext word c, and
// GHASH limb c. There is no transpose anywhere, which is what distinguishes this
// from the probe of section 17 -- that one kept sixteen messages per warp and
// paid two 4x4 transposes per block for it.
//
// The price is message parallelism: a warp of sixteen lanes now carries four
// messages instead of sixteen. That is the thing this kernel exists to measure.

// Rotate within the aligned quad: lane k receives lane `src` of the quad, where
// the descriptor was built with bval = src. See aes128_encrypt_sg4 for why the
// descriptor must be per-lane and why mask = 0x3c is the width-portable form.
__attribute__((always_inline))
inline uint32_t sg4_rot(uint32_t v, uint32_t desc) {
  size_t r;
  __asm__ volatile (".insn r %1, 7, 1, %0, %2, %3"
                    : "=r"(r)
                    : "i"(RISCV_CUSTOM0), "r"((size_t)v), "r"((size_t)desc));
  return (uint32_t)r;
}

inline uint32_t sg4_desc(uint32_t src_lane) {
  return (0x3cu << 12) | (3u << 6) | (src_lane & 3u);
}

// y = y * H over GF(2^128) with BOTH operands distributed: lane c holds limb c
// of y, and H is replicated because it is uniform for the whole key.
//
// The schoolbook product is p[i+j] ^= clmul(y[i],h[j]), p[i+j+1] ^= clmulh(...).
// Rotating y by j makes lane k hold y[(k-j)&3], so at step j lane k computes the
// term whose limb index is k when k >= j, and k+4 when the rotate wrapped. Each
// lane therefore accumulates two words: PL for p[k] and PH for p[k+4].
//
// The clmulh half of every term belongs one limb higher, which is the NEXT lane,
// so it is rotated up by one and steered on arrival: it lands in the high half
// when it came from lane 3 (p[4]) or when its source had wrapped (p[s+5]), and
// in the low half otherwise (p[s+1]).
//
// The fold is the same shape. p[k+4] times R contributes to r[k] in this lane
// and, through clmulh, to r[k+1] in the next -- except from lane 3, where it is
// the final carry and folds into r[0] with one more multiply.
//
// Predicates are arithmetic masks, not branches: the quad must stay converged
// because every step reads all four lanes.
//
// Every operand is a scalar, and the four steps are written out. Passing the H
// limbs and the rotate descriptors as arrays indexed by the loop counter puts
// them on the stack and reloads them in the innermost loop, which on this
// machine is the most expensive thing a kernel can do; see section 19.
template <int J>
__attribute__((always_inline))
inline void ghash_step_sg4(uint32_t c, uint32_t src_hi, uint32_t rot_j,
                           uint32_t rot_up1, uint32_t hj, uint32_t y,
                           uint32_t& pl, uint32_t& ph) {
  const uint32_t yj = (J == 0) ? y : sg4_rot(y, rot_j);
  const uint32_t lo = vx_clmul(yj, hj);
  const uint32_t hi = vx_clmulh(yj, hj);

  const uint32_t wrap = (uint32_t)0 - (uint32_t)(c < (uint32_t)J);
  pl ^= lo & ~wrap;
  ph ^= lo & wrap;

  const uint32_t up = sg4_rot(hi, rot_up1);
  const uint32_t tohi = (uint32_t)0
                      - (uint32_t)((c == 0u) | (src_hi < (uint32_t)J));
  pl ^= up & ~tohi;
  ph ^= up & tohi;
}

__attribute__((always_inline))
inline uint32_t ghash_mul_sg4(uint32_t c, uint32_t rot1, uint32_t rot2,
                              uint32_t rot3, uint32_t h0, uint32_t h1,
                              uint32_t h2, uint32_t h3, uint32_t y) {
  uint32_t pl = 0, ph = 0;
  const uint32_t src_hi = (c - 1u) & 3u;   // where this lane's clmulh comes from
  const uint32_t rot_up1 = rot1;

  ghash_step_sg4<0>(c, src_hi, 0u,   rot_up1, h0, y, pl, ph);
  ghash_step_sg4<1>(c, src_hi, rot1, rot_up1, h1, y, pl, ph);
  ghash_step_sg4<2>(c, src_hi, rot2, rot_up1, h2, y, pl, ph);
  ghash_step_sg4<3>(c, src_hi, rot3, rot_up1, h3, y, pl, ph);

  // fold p[4..7] back with x^128 == 0x87
  const uint32_t R = 0x87;
  pl ^= vx_clmul(ph, R);
  const uint32_t up2 = sg4_rot(vx_clmulh(ph, R), rot_up1);
  // lane 0 receives lane 3's, which is the carry out of the top limb
  pl ^= (c == 0u) ? vx_clmul(up2, R) : up2;
  return pl;
}


#ifdef VX_CFG_EXT_SYM_SG4_ENABLE
// The same round with the routing in hardware: one instruction per round in
// place of three rotates and four aes32. rs1 is this lane's round-key column,
// rs2 its state column, and the quad's ShiftRows is the fixed byte transpose
// inside the unit.
__attribute__((always_inline))
inline uint32_t aes128_encrypt_sg4f(const uint32_t* rk, uint32_t c,
                                    uint32_t in_col) {
  uint32_t s = in_col ^ rk[c];
  for (int round = 1; round < AES128_ROUNDS; ++round) {
    s = vx_aesrm_sg4(rk[4 * round + c], s);
  }
  return vx_aesrf_sg4(rk[4 * AES128_ROUNDS + c], s);
}
#endif

} // namespace

__kernel void aes_gcm_hw_s1(kernel_arg_t* __UNIFORM__ arg) {
  aes_gcm_hw_body<KS_LANE_LOCAL>(arg);
}

// The shipped kernel with ONLY the payload layout changed, so the difference
// between this row and hw_s1 is the streaming access pattern and nothing else.
// It measures the ceiling for the one mechanism the subgroup probe of section
// 17 left unrefuted; see section 18.
__kernel void aes_gcm_hw_s1_ilv(kernel_arg_t* __UNIFORM__ arg) {
  aes_gcm_hw_body<KS_LANE_LOCAL, LAYOUT_INTERLEAVED>(arg);
}

// Specimen, not a candidate: byte-for-byte the same work and the same addresses
// as aes_gcm_hw_s1, written as base-plus-offset. It is 20.6% slower. Kept so the
// measurement can be repeated and the mechanism chased; see section 18.2.
__kernel void aes_gcm_hw_s1_ofs(kernel_arg_t* __UNIFORM__ arg) {
  aes_gcm_hw_body<KS_LANE_LOCAL, LAYOUT_CONTIG_OFS>(arg);
}

// S3 PROBE -- subgroup-cooperative keystream, built out of instructions that
// already exist so the question can be measured before any RTL is written.
// It is expected to be SLOWER than aes_gcm_hw_s1: it issues the same number of
// aes32 per block (four lanes doing a quarter of the work each is the same
// warp-instruction count as one lane doing all of it), and adds three rotates
// per round plus two 4x4 transposes per block on top. What it measures is the
// conversion rate of that added issue pressure, which is what decides whether a
// fused subgroup round instruction -- which would delete the rotates and fold
// the four aes32 into one -- could ever clear this application's floor.
// See section 17 of docs/proposals/crypto_isa_proposal.md.
__kernel void aes_gcm_hw_sg4(kernel_arg_t* __UNIFORM__ arg) {
  aes_gcm_hw_body<KS_SUBGROUP_4>(arg);
}

// TRUE S3, built out of instructions that already exist: a quad owns one
// message end to end, the layout never changes, and there is no transpose. The
// AES path is the same aes128_encrypt_sg4 the section 17 probe used; what is new
// is that the ciphertext and the GHASH accumulator stay distributed too, so the
// quad never has to collect a block into one lane.
//
// Instruction count is deliberately NOT what this measures: in software the
// routing costs three rotates per AES round and eight per GHASH multiply, where
// a fused instruction would be wiring. What it measures is everything that is
// not derivable -- the memory access pattern, the register pressure, and the
// cost of carrying four messages per warp instead of sixteen.
namespace {

enum { S3_ROUTING_SOFTWARE = 0,   // shuffles for AES, software distributed GHASH
       S3_ROUTING_FUSED    = 1,   // aesrm.sg4 for AES, software distributed GHASH
       S3_ROUTING_FUSED_ALL = 2 };// aesrm.sg4 and ghmul.sg4

template <int ROUND>
inline void aes_gcm_hw_s3_body(kernel_arg_t* __UNIFORM__ arg) {
  hw_lmem_layout_t* lm = (hw_lmem_layout_t*)__local_mem();

  {
    const uint32_t* rk_src = (const uint32_t*)arg->rk_addr;
    const uint32_t tid = threadIdx.x;
    const uint32_t nthreads = blockDim.x;
    for (uint32_t i = tid; i < AES128_RK_BYTES / 4; i += nthreads) {
      lm->rk[i] = bswap32(rk_src[i]);
    }
  }
  __syncthreads();

  // Position in the quad, and the two rotate families. AES at byte step p wants
  // column (c+p)&3; GHASH at step j wants limb (c-j)&3. rot_up1 is the same
  // descriptor as rot_down[1] and is named separately because it is used for a
  // different purpose -- moving a clmulh term one limb up.
  const uint32_t c = (uint32_t)(vx_thread_id() & 3);
  const uint32_t ab1 = (c + 1u) & 3u;
  const uint32_t ab2 = (c + 2u) & 3u;
  const uint32_t ab3 = (c + 3u) & 3u;
  const uint32_t rot1 = sg4_desc(c - 1u);
  const uint32_t rot2 = sg4_desc(c - 2u);
  const uint32_t rot3 = sg4_desc(c - 3u);
  const uint32_t inc = (c == 3u) ? 1u : 0u;

  // H is uniform for the key, so every lane keeps all four limbs.
  const uint8_t* hp = (const uint8_t*)arg->h_addr;
  const uint32_t h0 = vx_brev8(load_le32(hp));
  const uint32_t h1 = vx_brev8(load_le32(hp + 4));
  const uint32_t h2 = vx_brev8(load_le32(hp + 8));
  const uint32_t h3 = vx_brev8(load_le32(hp + 12));
#ifdef VX_CFG_EXT_AUTH_SG4_ENABLE
  // The fused multiply wants only this lane's limb; the software path wants all
  // four, because every lane multiplies by every limb in turn.
  const uint32_t hcol = vx_brev8(load_le32(hp + 4 * c));
#endif

  const uint32_t num_msgs = arg->num_msgs;
  const uint32_t blocks = arg->blocks_per_msg;
  const uint32_t aad_bytes = arg->aad_bytes;
  const uint8_t* aad = (const uint8_t*)arg->aad_addr;
  const uint32_t msg_bytes = 16u * blocks;   // whole blocks only; main.cpp refuses a tail
  const uint8_t* iv_base = (const uint8_t*)arg->iv_addr;
  const uint8_t* src_base = (const uint8_t*)arg->src_addr;
  uint8_t* dst_base = (uint8_t*)arg->dst_addr;
  uint8_t* tag_base = (uint8_t*)arg->tag_addr;

  // One message per quad. All four lanes of a quad share the loop bound, so the
  // quad is always converged even when other quads in the warp have exited.
  const uint32_t quad = (blockIdx.x * blockDim.x + threadIdx.x) >> 2;
  const uint32_t qstride = (gridDim.x * blockDim.x) >> 2;

  for (uint32_t msg = quad; msg < num_msgs; msg += qstride) {
    const uint8_t* iv = iv_base + GCM_IV_BYTES * msg;
    // Lane c takes word c of J0; the trailing word is the counter, not the IV.
    const uint32_t j0 = (c == 3u) ? 0x01000000u : load_le32(iv + 4 * c);
    uint32_t ctr = j0;
    uint32_t y = 0;

    for (uint32_t off = 0; off < aad_bytes; off += 16) {
      uint8_t pb[4] = {0};
      for (uint32_t i = 0; i < 4; ++i) {
        const uint32_t k = off + 4 * c + i;
        if (k < aad_bytes) {
          pb[i] = aad[k];
        }
      }
      y ^= vx_brev8(load_le32(pb));
      #ifdef VX_CFG_EXT_AUTH_SG4_ENABLE
      if (ROUND == S3_ROUTING_FUSED_ALL) {
        y = vx_ghmul_sg4(y, hcol);
      } else
#endif
      {
        y = ghash_mul_sg4(c, rot1, rot2, rot3, h0, h1, h2, h3, y);
      }
    }

    const uint8_t* pt = src_base + (size_t)msg_bytes * msg;
    uint8_t* ct = dst_base + (size_t)msg_bytes * msg;

    // Unrolled by hand's width rather than left to the compiler: with the
    // routing fused the loop body is small enough that clang stops unrolling it,
    // and the per-iteration counter, address and branch work then costs more
    // than the instructions the fusion removed.
#pragma unroll 2
    for (uint32_t b = 0; b < blocks; ++b) {
      // inc32 touches only the trailing word, which lives in lane 3 -- but it is
      // written branchlessly, because every rotate inside the AES below needs
      // the quad converged and a divergent region here is enough to break it.
      // Lanes 0-2 add zero, and bswap32 applied twice is the identity.
      ctr = bswap32(bswap32(ctr) + inc);
      uint32_t ks;
#ifdef VX_CFG_EXT_SYM_SG4_ENABLE
      // Both fused modes use the fused round; only S3_ROUTING_SOFTWARE does not.
      if (ROUND != S3_ROUTING_SOFTWARE) {
        ks = aes128_encrypt_sg4f(lm->rk, c, ctr);
      } else
#endif
      {
        ks = aes128_encrypt_sg4(lm->rk, c, ab1, ab2, ab3, ctr);
      }
      // Four lanes read four consecutive words of the same block, so a quad
      // touches sixteen contiguous bytes where the lane-local kernel touches
      // sixteen lines msg_stride apart.
      const uint32_t* pt_w = (const uint32_t*)(pt + 16 * b);
      uint32_t* ct_w = (uint32_t*)(ct + 16 * b);
      const uint32_t cw = pt_w[c] ^ ks;
      ct_w[c] = cw;
      y ^= vx_brev8(cw);
      #ifdef VX_CFG_EXT_AUTH_SG4_ENABLE
      if (ROUND == S3_ROUTING_FUSED_ALL) {
        y = vx_ghmul_sg4(y, hcol);
      } else
#endif
      {
        y = ghash_mul_sg4(c, rot1, rot2, rot3, h0, h1, h2, h3, y);
      }
    }

    // Length block: [len(A)]64 || [len(C)]64, one big-endian word per lane.
    const uint64_t abits = (uint64_t)aad_bytes * 8u;
    const uint64_t cbits = (uint64_t)msg_bytes * 8u;
    uint32_t lw;
    if (c == 0u) {
      lw = (uint32_t)(abits >> 32);
    } else if (c == 1u) {
      lw = (uint32_t)abits;
    } else if (c == 2u) {
      lw = (uint32_t)(cbits >> 32);
    } else {
      lw = (uint32_t)cbits;
    }
    y ^= vx_brev8(bswap32(lw));
    #ifdef VX_CFG_EXT_AUTH_SG4_ENABLE
      if (ROUND == S3_ROUTING_FUSED_ALL) {
        y = vx_ghmul_sg4(y, hcol);
      } else
#endif
      {
        y = ghash_mul_sg4(c, rot1, rot2, rot3, h0, h1, h2, h3, y);
      }

    uint32_t ej0;
#ifdef VX_CFG_EXT_SYM_SG4_ENABLE
    if (ROUND != S3_ROUTING_SOFTWARE) {
      ej0 = aes128_encrypt_sg4f(lm->rk, c, j0);
    } else
#endif
    {
      ej0 = aes128_encrypt_sg4(lm->rk, c, ab1, ab2, ab3, j0);
    }
    uint8_t* tag = tag_base + GCM_TAG_BYTES * msg;
    store_le32(tag + 4 * c, vx_brev8(y) ^ ej0);
  }
}


// ---------------------------------------------------------------------------
// S2: one lane still owns one message, but the 128-bit state moves out of the
// general-purpose registers and into a per-(warp, lane) context, so one
// instruction advances a whole AES round or a whole GHASH block update.
//
// The message-to-lane mapping is the SAME as hw_s1 -- sixteen messages per warp
// at t16 -- which is what separates S2 from S3. Only the instruction granularity
// changes, so a comparison against hw_s1 isolates granularity from layout.

#ifdef VX_CFG_EXT_SYM_S2_ENABLE
// One AES-128 encryption out of the lane's own context. The counter block is
// packed exactly as aes128_encrypt_hw packs it -- one column per word, row 0 in
// the low byte -- because the engine reuses this unit's existing byte order.
__attribute__((always_inline))
inline void aes128_encrypt_s2(const uint32_t in[4], uint32_t out[4]) {
  vx_aes_cwr(in[0], 0);
  vx_aes_cwr(in[1], 1);
  vx_aes_cwr(in[2], 2);
  vx_aes_cwr(in[3], 3);
  // begin leaves rnd = 1, so the first middle round produces K1 with Rcon[1].
  vx_aes_begin();
  vx_aes_rndm();   // round 1
  vx_aes_rndm();
  vx_aes_rndm();
  vx_aes_rndm();
  vx_aes_rndm();
  vx_aes_rndm();
  vx_aes_rndm();
  vx_aes_rndm();
  vx_aes_rndm();   // round 9
  vx_aes_rndf();   // round 10, no MixColumns
  out[0] = vx_aes_crd(0);
  out[1] = vx_aes_crd(1);
  out[2] = vx_aes_crd(2);
  out[3] = vx_aes_crd(3);
}
#endif

#ifdef VX_CFG_EXT_AUTH_S2_ENABLE
// Y <- (Y ^ X)*H for this lane. The XOR that the software path writes as
// `y[i] ^= v` is inside the instruction, so the accumulator never leaves the
// context and the kernel only supplies X.
__attribute__((always_inline))
inline void ghash_absorb_s2(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3) {
  vx_ghash_cwr(x0, 0);
  vx_ghash_cwr(x1, 1);
  vx_ghash_cwr(x2, 2);
  vx_ghash_cwr(x3, 3);
  vx_ghash_block();
}
#endif

#ifdef VX_CFG_EXT_SYM_S2_ENABLE
enum { S2_AES_ONLY = 0,   // stateful AES, software GHASH -- isolates the round
       S2_BOTH     = 1 }; // stateful AES and stateful GHASH

template <int ENGINE, int LAYOUT = LAYOUT_CONTIG>
inline void aes_gcm_hw_s2_body(kernel_arg_t* __UNIFORM__ arg) {
  // No local memory and no key schedule: the engine derives K1..K10 from K0 on
  // the fly, so only the cipher key is uploaded. That is four words per thread
  // once, against the 44 the shipped kernel copies into LMEM per CTA.
  uint32_t k0[4];
  {
    const uint32_t* rk_src = (const uint32_t*)arg->rk_addr;
    for (int i = 0; i < 4; ++i) {
      k0[i] = bswap32(rk_src[i]);
    }
  }
  vx_aes_cwr(k0[0], 4);
  vx_aes_cwr(k0[1], 5);
  vx_aes_cwr(k0[2], 6);
  vx_aes_cwr(k0[3], 7);

  uint32_t h[4];
  {
    const uint8_t* hp = (const uint8_t*)arg->h_addr;
    for (int i = 0; i < 4; ++i) {
      h[i] = vx_brev8(load_le32(hp + 4 * i));
    }
  }
#ifdef VX_CFG_EXT_AUTH_S2_ENABLE
  if (ENGINE == S2_BOTH) {
    vx_ghash_cwr(h[0], 4);
    vx_ghash_cwr(h[1], 5);
    vx_ghash_cwr(h[2], 6);
    vx_ghash_cwr(h[3], 7);
  }
#endif

  const uint32_t num_msgs = arg->num_msgs;
  const uint32_t blocks = arg->blocks_per_msg;
  const uint32_t tail = arg->tail_bytes;
  const uint32_t aad_bytes = arg->aad_bytes;
  const uint8_t* aad = (const uint8_t*)arg->aad_addr;
  const uint32_t msg_bytes = 16u * blocks + tail;
  const uint32_t msg_stride = 16u * (blocks + (tail != 0u ? 1u : 0u));
  const uint8_t* iv_base = (const uint8_t*)arg->iv_addr;
  const uint8_t* src_base = (const uint8_t*)arg->src_addr;
  uint8_t* dst_base = (uint8_t*)arg->dst_addr;
  uint8_t* tag_base = (uint8_t*)arg->tag_addr;

  const uint32_t stride = gridDim.x * blockDim.x;
  for (uint32_t msg = blockIdx.x * blockDim.x + threadIdx.x; msg < num_msgs;
       msg += stride) {
    const uint8_t* iv = iv_base + GCM_IV_BYTES * msg;
    uint32_t j0[4];
    j0[0] = load_le32(iv);
    j0[1] = load_le32(iv + 4);
    j0[2] = load_le32(iv + 8);
    j0[3] = 0x01000000u;

    uint32_t ctr[4] = {j0[0], j0[1], j0[2], j0[3]};
    // Only the software-GHASH arm keeps an accumulator in registers; with the
    // stateful engine Y lives in the context and is reset by ghash.init.
    uint32_t y[4] = {0, 0, 0, 0};
#ifdef VX_CFG_EXT_AUTH_S2_ENABLE
    if (ENGINE == S2_BOTH) {
      vx_ghash_init();
    }
#endif

    for (uint32_t off = 0; off < aad_bytes; off += 16) {
      const uint32_t n = (aad_bytes - off < 16u) ? (aad_bytes - off) : 16u;
      uint8_t padded[16] = {0};
      for (uint32_t i = 0; i < n; ++i) {
        padded[i] = aad[off + i];
      }
#ifdef VX_CFG_EXT_AUTH_S2_ENABLE
      if (ENGINE == S2_BOTH) {
        ghash_absorb_s2(vx_brev8(load_le32(padded)),
                        vx_brev8(load_le32(padded + 4)),
                        vx_brev8(load_le32(padded + 8)),
                        vx_brev8(load_le32(padded + 12)));
      } else
#endif
      {
        for (int i = 0; i < 4; ++i) {
          y[i] ^= vx_brev8(load_le32(padded + 4 * i));
        }
        ghash_mul_hw(h, y);
      }
    }

    const uint8_t* pt = src_base + (size_t)msg_stride * msg;
    uint8_t* ct = dst_base + (size_t)msg_stride * msg;

    for (uint32_t b = 0; b < blocks; ++b) {
      ctr[3] = bswap32(bswap32(ctr[3]) + 1);

      uint32_t ks[4];
      aes128_encrypt_s2(ctr, ks);

      // Same pointer-walk addressing as the shipped kernel: section 18.2
      // records that writing this as base-plus-offset costs 20.6% of the
      // cycles, which would swamp what this kernel is here to measure. The
      // interleaved arm exists because comparing S2 against the S3 rows
      // otherwise confounds instruction granularity with memory layout: S3
      // coalesces because a quad's four lanes touch consecutive words, and S2
      // inherits S1's sixteen scattered messages.
      const uint32_t* pt_w;
      uint32_t* ct_w;
      if (LAYOUT == LAYOUT_INTERLEAVED) {
        const size_t blk = (size_t)16 * ((size_t)b * num_msgs + msg);
        pt_w = (const uint32_t*)(src_base + blk);
        ct_w = (uint32_t*)(dst_base + blk);
      } else {
        pt_w = (const uint32_t*)(pt + 16 * b);
        ct_w = (uint32_t*)(ct + 16 * b);
      }
      uint32_t c[4];
      for (int i = 0; i < 4; ++i) {
        c[i] = pt_w[i] ^ ks[i];
        ct_w[i] = c[i];
      }
#ifdef VX_CFG_EXT_AUTH_S2_ENABLE
      if (ENGINE == S2_BOTH) {
        ghash_absorb_s2(vx_brev8(c[0]), vx_brev8(c[1]),
                        vx_brev8(c[2]), vx_brev8(c[3]));
      } else
#endif
      {
        for (int i = 0; i < 4; ++i) {
          y[i] ^= vx_brev8(c[i]);
        }
        ghash_mul_hw(h, y);
      }
    }

    if (tail != 0) {
      ctr[3] = bswap32(bswap32(ctr[3]) + 1);
      uint32_t ks[4];
      aes128_encrypt_s2(ctr, ks);
      uint8_t padded[16] = {0};
      for (uint32_t i = 0; i < tail; ++i) {
        const uint8_t k = (uint8_t)(ks[i >> 2] >> (8 * (i & 3)));
        const uint8_t cb = (uint8_t)(pt[16 * blocks + i] ^ k);
        ct[16 * blocks + i] = cb;
        padded[i] = cb;
      }
#ifdef VX_CFG_EXT_AUTH_S2_ENABLE
      if (ENGINE == S2_BOTH) {
        ghash_absorb_s2(vx_brev8(load_le32(padded)),
                        vx_brev8(load_le32(padded + 4)),
                        vx_brev8(load_le32(padded + 8)),
                        vx_brev8(load_le32(padded + 12)));
      } else
#endif
      {
        for (int i = 0; i < 4; ++i) {
          y[i] ^= vx_brev8(load_le32(padded + 4 * i));
        }
        ghash_mul_hw(h, y);
      }
    }

    const uint64_t abits = (uint64_t)aad_bytes * 8u;
    const uint64_t cbits = (uint64_t)msg_bytes * 8u;
#ifdef VX_CFG_EXT_AUTH_S2_ENABLE
    if (ENGINE == S2_BOTH) {
      ghash_absorb_s2(vx_brev8(bswap32((uint32_t)(abits >> 32))),
                      vx_brev8(bswap32((uint32_t)abits)),
                      vx_brev8(bswap32((uint32_t)(cbits >> 32))),
                      vx_brev8(bswap32((uint32_t)cbits)));
      y[0] = vx_ghash_crd(0);
      y[1] = vx_ghash_crd(1);
      y[2] = vx_ghash_crd(2);
      y[3] = vx_ghash_crd(3);
    } else
#endif
    {
      y[0] ^= vx_brev8(bswap32((uint32_t)(abits >> 32)));
      y[1] ^= vx_brev8(bswap32((uint32_t)abits));
      y[2] ^= vx_brev8(bswap32((uint32_t)(cbits >> 32)));
      y[3] ^= vx_brev8(bswap32((uint32_t)cbits));
      ghash_mul_hw(h, y);
    }

    uint32_t ej0[4];
    aes128_encrypt_s2(j0, ej0);
    uint8_t* tag = tag_base + GCM_TAG_BYTES * msg;
    for (int i = 0; i < 4; ++i) {
      store_le32(tag + 4 * i, vx_brev8(y[i]) ^ ej0[i]);
    }
  }
}
#endif  // VX_CFG_EXT_SYM_S2_ENABLE

} // namespace

#ifdef VX_CFG_EXT_SYM_S2_ENABLE
// Stateful AES round, software GHASH. Isolates the round instruction the way
// hw_s3f isolates the fused subgroup round.
__kernel void aes_gcm_hw_s2a(kernel_arg_t* __UNIFORM__ arg) {
  aes_gcm_hw_s2_body<S2_AES_ONLY>(arg);
}
#endif

#if defined(VX_CFG_EXT_SYM_S2_ENABLE) && defined(VX_CFG_EXT_AUTH_S2_ENABLE)
// Both engines stateful: one instruction per AES round and one per GHASH block.
__kernel void aes_gcm_hw_s2(kernel_arg_t* __UNIFORM__ arg) {
  aes_gcm_hw_s2_body<S2_BOTH>(arg);
}

// The same kernel with ONLY the payload layout changed, so that the difference
// against the S3 rows can be attributed to granularity rather than coalescing.
__kernel void aes_gcm_hw_s2_ilv(kernel_arg_t* __UNIFORM__ arg) {
  aes_gcm_hw_s2_body<S2_BOTH, LAYOUT_INTERLEAVED>(arg);
}
#endif

__kernel void aes_gcm_hw_s3(kernel_arg_t* __UNIFORM__ arg) {
  aes_gcm_hw_s3_body<S3_ROUTING_SOFTWARE>(arg);
}

#ifdef VX_CFG_EXT_SYM_SG4_ENABLE
// The same kernel with the cross-lane routing done by the instruction instead
// of by three shuffles per round. Everything else -- the layout, the payload
// pattern, the distributed GHASH, the four messages per warp -- is identical,
// so the difference between this row and hw_s3 is the fused round and nothing
// else.
__kernel void aes_gcm_hw_s3f(kernel_arg_t* __UNIFORM__ arg) {
  aes_gcm_hw_s3_body<S3_ROUTING_FUSED>(arg);
}
#endif

#if defined(VX_CFG_EXT_SYM_SG4_ENABLE) && defined(VX_CFG_EXT_AUTH_SG4_ENABLE)
// Both halves fused: one instruction per AES round and one per GHASH block.
// Everything else is identical to hw_s3 and hw_s3f, so the three rows differ
// only in how much of the routing is an instruction.
__kernel void aes_gcm_hw_s3g(kernel_arg_t* __UNIFORM__ arg) {
  aes_gcm_hw_s3_body<S3_ROUTING_FUSED_ALL>(arg);
}
#endif
