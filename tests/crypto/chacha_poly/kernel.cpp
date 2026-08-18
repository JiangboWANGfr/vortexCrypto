#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include "common.h"

// One CTA per core, one independent ChaCha20-Poly1305 message per thread.
// No local memory: neither half of this AEAD reads a table, so there is
// nothing to stage and nothing to fence.
//
// Everything below works on 32-bit words rather than bytes. Both halves are
// defined over little-endian words, and RV32 is little-endian, so a native
// word load of the payload already is the value the specification asks for.
// The buffers are allocated by the runtime and indexed at 64-byte multiples,
// so the word pointers are aligned.

namespace {

inline uint32_t load_le32(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
       | ((uint32_t)p[3] << 24);
}

// always_inline on the helpers below is load-bearing rather than decoration.
// Their array parameters -- the sixteen-word ChaCha state, the sixteen-word
// keystream, the Poly1305 context -- make LLVM decline to inline them at -O3
// despite the `inline`, which forces those arrays into stack slots. That is the
// worst-shaped traffic on this machine: vx_start.S puts each hart's stack 8 KB
// from the next, so one stack access in a warp is NUM_THREADS distinct cache
// lines, and with DCACHE_NUM_BANKS = 1, one DDR4 channel and no L2 or L3 there
// is nothing behind the L1 to absorb them.
//
// Verified statically rather than assumed: without these attributes the binary
// carries an out-of-line chacha20_block of 252 instructions and the kernels
// hold 235 stack references; with them the out-of-line copies are gone.
//
// The two entry points below differ in exactly one thing: how a 32-bit left
// rotate is spelled. The round schedule, the Poly1305 limbs and the memory
// access pattern are shared code, so a comparison between the two rows
// measures the rotate and nothing else.
//
// `rot_sw` is what rv32imaf can express: three instructions, two of them
// independent, so the rotate is two levels of the dependency chain. `rot_hw`
// is the ratified Zbb/Zbkb RORI, one instruction and one level.
struct rot_sw {
  template <int N> static inline uint32_t rotl(uint32_t v) {
    return (uint32_t)((v << N) | (v >> (32 - N)));
  }
};

struct rot_hw {
  template <int N> static inline uint32_t rotl(uint32_t v) {
    return vx_rotl32(v, N);
  }
};

// RFC 8439 section 2.1. Four adds, four xors and four rotates.
template <typename R>
__attribute__((always_inline)) inline void quarter_round(uint32_t x[16], int a, int b, int c, int d) {
  x[a] += x[b]; x[d] ^= x[a]; x[d] = R::template rotl<16>(x[d]);
  x[c] += x[d]; x[b] ^= x[c]; x[b] = R::template rotl<12>(x[b]);
  x[a] += x[b]; x[d] ^= x[a]; x[d] = R::template rotl<8>(x[d]);
  x[c] += x[d]; x[b] ^= x[c]; x[b] = R::template rotl<7>(x[b]);
}

// RFC 8439 section 2.3. The permutation alone, leaving the sixteen keystream words in x[]. Split out
// so that the two callers can consume x[] differently without the rounds being
// written twice: the once-per-message Poly1305 key wants the raw words, the
// per-block path wants them XORed and gone.
template <typename R, bool PERM>
__attribute__((always_inline)) inline void chacha20_keystream(
    const uint32_t k[8], uint32_t n0, uint32_t n1, uint32_t n2,
    uint32_t counter, uint32_t x[16]) {
  x[0] = 0x61707865; x[1] = 0x3320646e;
  x[2] = 0x79622d32; x[3] = 0x6b206574;
  for (int i = 0; i < 8; ++i) {
    x[4 + i] = k[i];
  }
  x[12] = counter; x[13] = n0; x[14] = n1; x[15] = n2;

  for (int i = 0; i < CHACHA_ROUNDS / 2; ++i) {
    if (PERM) {
      // The four quarter-rounds of a column round touch disjoint columns, and
      // likewise the diagonal round, so issuing them in the reverse order is
      // bit-identical by construction rather than merely equivalent. This
      // exists to measure the apparatus, not the cipher: two kernels that must
      // produce the same cycles, so that the distance between them is the
      // floor below which no result here is legible.
      quarter_round<R>(x, 3, 7, 11, 15);
      quarter_round<R>(x, 2, 6, 10, 14);
      quarter_round<R>(x, 1, 5, 9, 13);
      quarter_round<R>(x, 0, 4, 8, 12);
      quarter_round<R>(x, 3, 4, 9, 14);
      quarter_round<R>(x, 2, 7, 8, 13);
      quarter_round<R>(x, 1, 6, 11, 12);
      quarter_round<R>(x, 0, 5, 10, 15);
    } else {
      quarter_round<R>(x, 0, 4, 8, 12);
      quarter_round<R>(x, 1, 5, 9, 13);
      quarter_round<R>(x, 2, 6, 10, 14);
      quarter_round<R>(x, 3, 7, 11, 15);
      quarter_round<R>(x, 0, 5, 10, 15);
      quarter_round<R>(x, 1, 6, 11, 12);
      quarter_round<R>(x, 2, 7, 8, 13);
      quarter_round<R>(x, 3, 4, 9, 14);
    }
  }

  // Feedforward in place. The initial state is not held live across the rounds:
  // its words are constants, the key, the counter and the nonce, all still in
  // registers, so they are rebuilt here rather than kept as a second copy.
  x[0] += 0x61707865; x[1] += 0x3320646e;
  x[2] += 0x79622d32; x[3] += 0x6b206574;
  for (int i = 0; i < 8; ++i) {
    x[4 + i] += k[i];
  }
  x[12] += counter;
  x[13] += n0;
  x[14] += n1;
  x[15] += n2;
}

// One payload block: permute, then XOR, store and absorb four words at a time.
//
// The point of fusing these is that the keystream never becomes a value with a
// lifetime. Written into its own array by one loop and read back by another, it
// has to materialise, and on this machine materialising means the stack -- 8 KB
// per hart, so NUM_THREADS distinct cache lines per access, through one D-cache
// bank into one DDR4 channel with no L2 or L3 behind it. Consumed in place, it
// is only ever sixteen live values.
struct poly1305_t {
  uint32_t r0, r1, r2, r3, r4;
  uint32_t s1, s2, s3, s4; // r1..r4 times five, the reduction of 2^130 == 5
  uint32_t h0, h1, h2, h3, h4;
  uint32_t pad0, pad1, pad2, pad3;
};


// The masks do the clamping of RFC 8439 section 2.5 as they repack.
__attribute__((always_inline)) inline void poly1305_init(poly1305_t& st, const uint32_t pk[8]) {
  const uint32_t t0 = pk[0], t1 = pk[1], t2 = pk[2], t3 = pk[3];
  st.r0 = t0 & 0x3ffffff;
  st.r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
  st.r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
  st.r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
  st.r4 = (t3 >> 8) & 0x00fffff;
  st.s1 = st.r1 * 5; st.s2 = st.r2 * 5;
  st.s3 = st.r3 * 5; st.s4 = st.r4 * 5;
  st.h0 = 0; st.h1 = 0; st.h2 = 0; st.h3 = 0; st.h4 = 0;
  st.pad0 = pk[4]; st.pad1 = pk[5]; st.pad2 = pk[6]; st.pad3 = pk[7];
}

// h = (h + block) * r mod 2^130-5, for a full sixteen-byte block.
__attribute__((always_inline)) inline void poly1305_block(poly1305_t& st, uint32_t t0, uint32_t t1,
                           uint32_t t2, uint32_t t3) {
  uint32_t h0 = st.h0 + (t0 & 0x3ffffff);
  uint32_t h1 = st.h1 + (((t0 >> 26) | (t1 << 6)) & 0x3ffffff);
  uint32_t h2 = st.h2 + (((t1 >> 20) | (t2 << 12)) & 0x3ffffff);
  uint32_t h3 = st.h3 + (((t2 >> 14) | (t3 << 18)) & 0x3ffffff);
  uint32_t h4 = st.h4 + ((t3 >> 8) | (1u << 24)); // the appended 0x01 byte

  uint64_t d0 = (uint64_t)h0 * st.r0 + (uint64_t)h1 * st.s4
              + (uint64_t)h2 * st.s3 + (uint64_t)h3 * st.s2
              + (uint64_t)h4 * st.s1;
  uint64_t d1 = (uint64_t)h0 * st.r1 + (uint64_t)h1 * st.r0
              + (uint64_t)h2 * st.s4 + (uint64_t)h3 * st.s3
              + (uint64_t)h4 * st.s2;
  uint64_t d2 = (uint64_t)h0 * st.r2 + (uint64_t)h1 * st.r1
              + (uint64_t)h2 * st.r0 + (uint64_t)h3 * st.s4
              + (uint64_t)h4 * st.s3;
  uint64_t d3 = (uint64_t)h0 * st.r3 + (uint64_t)h1 * st.r2
              + (uint64_t)h2 * st.r1 + (uint64_t)h3 * st.r0
              + (uint64_t)h4 * st.s4;
  uint64_t d4 = (uint64_t)h0 * st.r4 + (uint64_t)h1 * st.r3
              + (uint64_t)h2 * st.r2 + (uint64_t)h3 * st.r1
              + (uint64_t)h4 * st.r0;

  uint32_t c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
  d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
  d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
  d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
  d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
  h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
  h1 += c;

  st.h0 = h0; st.h1 = h1; st.h2 = h2; st.h3 = h3; st.h4 = h4;
}

__attribute__((always_inline)) inline void poly1305_finish(poly1305_t& st, uint32_t tag[4]) {
  uint32_t h0 = st.h0, h1 = st.h1, h2 = st.h2, h3 = st.h3, h4 = st.h4;

  uint32_t c = h1 >> 26; h1 &= 0x3ffffff;
  h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
  h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
  h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
  h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
  h1 += c;

  // g = h + 5, which is h - (2^130-5) once bit 130 is dropped.
  uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
  uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
  uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
  uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
  uint32_t g4 = h4 + c - (1u << 26);

  // Branchless select: g4 borrowed exactly when h was already reduced.
  uint32_t mask = (g4 >> 31) - 1;
  g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
  mask = ~mask;
  h0 = (h0 & mask) | g0;
  h1 = (h1 & mask) | g1;
  h2 = (h2 & mask) | g2;
  h3 = (h3 & mask) | g3;
  h4 = (h4 & mask) | g4;

  h0 = h0 | (h1 << 26);
  h1 = (h1 >> 6) | (h2 << 20);
  h2 = (h2 >> 12) | (h3 << 14);
  h3 = (h3 >> 18) | (h4 << 8);

  uint64_t f = (uint64_t)h0 + st.pad0; h0 = (uint32_t)f;
  f = (uint64_t)h1 + st.pad1 + (f >> 32); h1 = (uint32_t)f;
  f = (uint64_t)h2 + st.pad2 + (f >> 32); h2 = (uint32_t)f;
  f = (uint64_t)h3 + st.pad3 + (f >> 32); h3 = (uint32_t)f;

  tag[0] = h0; tag[1] = h1; tag[2] = h2; tag[3] = h3;
}

// `arg` keeps its __UNIFORM__ annotation here as well as on the two kernel
// entry points below: dropping it on this side costs 1304 retired instructions
// at the recorded point, because the per-message argument loads stop being
// hoisted as uniform. Measured, not assumed.
template <typename R, bool PERM>
__attribute__((always_inline)) inline void chacha20_xor_absorb(
    const uint32_t k[8], uint32_t n0, uint32_t n1, uint32_t n2,
    uint32_t counter, const uint32_t* pb, uint32_t* cb, poly1305_t& st) {
  uint32_t x[16];
  chacha20_keystream<R, PERM>(k, n0, n1, n2, counter, x);

  for (int q = 0; q < 4; ++q) {
    const uint32_t c0 = pb[4 * q + 0] ^ x[4 * q + 0];
    const uint32_t c1 = pb[4 * q + 1] ^ x[4 * q + 1];
    const uint32_t c2 = pb[4 * q + 2] ^ x[4 * q + 2];
    const uint32_t c3 = pb[4 * q + 3] ^ x[4 * q + 3];
    cb[4 * q + 0] = c0;
    cb[4 * q + 1] = c1;
    cb[4 * q + 2] = c2;
    cb[4 * q + 3] = c3;
    poly1305_block(st, c0, c1, c2, c3);
  }
}

// Poly1305 with the accumulator in five 26-bit limbs, so a 26x26 product fits
// a 32x32 multiply and the carries out of five of them still fit 64 bits.
// RV32 has no multiply-accumulate, so each partial product is a mul/mulhu
// pair; that is the cost the S1 work has to beat.
template <typename R, bool PERM = false>
inline void chacha_poly_body(kernel_arg_t* __UNIFORM__ arg) {
  const uint32_t* key = (const uint32_t*)arg->key_addr;
  const uint8_t* nonce_base = (const uint8_t*)arg->nonce_addr;
  const uint32_t* src_base = (const uint32_t*)arg->src_addr;
  uint32_t* dst_base = (uint32_t*)arg->dst_addr;
  uint32_t* tag_base = (uint32_t*)arg->tag_addr;

  const uint32_t num_msgs = arg->num_msgs;
  const uint32_t blocks = arg->blocks_per_msg;
  const uint32_t words = blocks * (CHACHA_BLOCK_BYTES / 4);

  uint32_t k[8];
  for (int i = 0; i < 8; ++i) {
    k[i] = key[i];
  }

  const uint32_t stride = gridDim.x * blockDim.x;
  for (uint32_t msg = blockIdx.x * blockDim.x + threadIdx.x; msg < num_msgs;
       msg += stride) {
    const uint8_t* np = nonce_base + CHACHA_NONCE_BYTES * msg;
    const uint32_t n0 = load_le32(np);
    const uint32_t n1 = load_le32(np + 4);
    const uint32_t n2 = load_le32(np + 8);

    // The one-time Poly1305 key is the keystream at counter zero. It depends
    // on the nonce, so it is per message and cannot be hoisted to the host.
    uint32_t ks[16];
    chacha20_keystream<R, PERM>(k, n0, n1, n2, 0, ks);
    poly1305_t st;
    poly1305_init(st, ks);

    const uint32_t* pt = src_base + (size_t)words * msg;
    uint32_t* ct = dst_base + (size_t)words * msg;
    for (uint32_t b = 0; b < blocks; ++b) {
      chacha20_xor_absorb<R, PERM>(k, n0, n1, n2, b + 1, pt + 16 * b,
                                   ct + 16 * b, st);
    }

    // The AAD is empty and the ciphertext is a whole number of Poly1305
    // blocks, so neither pad16 contributes anything and the length block is
    // the only trailer: le64(0) || le64(ciphertext bytes).
    const uint64_t ct_bytes = (uint64_t)blocks * CHACHA_BLOCK_BYTES;
    poly1305_block(st, 0, 0, (uint32_t)ct_bytes, (uint32_t)(ct_bytes >> 32));

    uint32_t tag[4];
    poly1305_finish(st, tag);
    uint32_t* tp = tag_base + 4 * msg;
    for (int i = 0; i < 4; ++i) {
      tp[i] = tag[i];
    }
  }
}

} // namespace

__kernel void chacha_poly_sw(kernel_arg_t* __UNIFORM__ arg) {
  chacha_poly_body<rot_sw, false>(arg);
}

// Bit-identical to chacha_poly_sw. Its only purpose is to measure the distance
// between two kernels that cannot differ, which is the floor below which a
// result from this application is not legible.
__kernel void chacha_poly_sw_perm(kernel_arg_t* __UNIFORM__ arg) {
  chacha_poly_body<rot_sw, true>(arg);
}

// Same code with RORI. This is not a cryptographic instruction, so this row is
// a stronger software baseline rather than an instruction-set extension --
// see sw/kernel/include/crypto/vx_chacha.h.
__kernel void chacha_poly_rori(kernel_arg_t* __UNIFORM__ arg) {
  chacha_poly_body<rot_hw, false>(arg);
}
