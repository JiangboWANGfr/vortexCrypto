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
    const uint32_t t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff]
                      ^ te2[(s2 >> 8) & 0xff] ^ te3[s3 & 0xff] ^ k[0];
    const uint32_t t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff]
                      ^ te2[(s3 >> 8) & 0xff] ^ te3[s0 & 0xff] ^ k[1];
    const uint32_t t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff]
                      ^ te2[(s0 >> 8) & 0xff] ^ te3[s1 & 0xff] ^ k[2];
    const uint32_t t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff]
                      ^ te2[(s1 >> 8) & 0xff] ^ te3[s2 & 0xff] ^ k[3];
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

__kernel void aes_gcm_sw_ttable(kernel_arg_t* __UNIFORM__ arg) {
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
    const uint8_t* pt = src_base + (size_t)AES_BLOCK_BYTES * blocks * msg;
    uint8_t* ct = dst_base + (size_t)AES_BLOCK_BYTES * blocks * msg;
    for (uint32_t b = 0; b < blocks; ++b) {
      inc32(ctr);
      uint8_t ks[16];
      aes128_encrypt(lm, ctr, ks);
      for (int i = 0; i < 16; ++i) {
        const uint8_t c = (uint8_t)(pt[16 * b + i] ^ ks[i]);
        ct[16 * b + i] = c;
        y[i] ^= c;
      }
      ghash_mul(lm->htable, y);
    }

    const uint64_t cbits = (uint64_t)blocks * 128u;
    for (int i = 0; i < 8; ++i) {
      y[15 - i] ^= (uint8_t)(cbits >> (8 * i));
    }
    ghash_mul(lm->htable, y);

    uint8_t ej0[16];
    aes128_encrypt(lm, j0, ej0);
    uint8_t* tag = tag_base + GCM_TAG_BYTES * msg;
    for (int i = 0; i < 16; ++i) {
      tag[i] = (uint8_t)(y[i] ^ ej0[i]);
    }
  }
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

// y = y * h over GF(2^128) mod x^128 + x^7 + x^2 + x + 1, both in the
// reflected limb domain. Schoolbook 4x4; Karatsuba trades 14 clmul for 11 xor
// here, which is a wash at this width and is not worth the complexity until
// clmul is measured to be more expensive than an xor.
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

} // namespace

__kernel void aes_gcm_hw_s1(kernel_arg_t* __UNIFORM__ arg) {
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

    const uint8_t* pt = src_base + (size_t)AES_BLOCK_BYTES * blocks * msg;
    uint8_t* ct = dst_base + (size_t)AES_BLOCK_BYTES * blocks * msg;

    for (uint32_t b = 0; b < blocks; ++b) {
      // inc32 on the trailing big-endian counter word
      ctr[3] = bswap32(bswap32(ctr[3]) + 1);

      uint32_t ks[4];
      aes128_encrypt_hw(lm->rk, ctr, ks);

      for (int i = 0; i < 4; ++i) {
        const uint32_t c = load_le32(pt + 16 * b + 4 * i) ^ ks[i];
        store_le32(ct + 16 * b + 4 * i, c);
        y[i] ^= vx_brev8(c);
      }
      ghash_mul_hw(h, y);
    }

    // Length block: [len(A)]64 || [len(C)]64, big-endian, so the two 32-bit
    // halves land byte-swapped in the little-endian limbs before reflection.
    const uint64_t cbits = (uint64_t)blocks * 128u;
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
