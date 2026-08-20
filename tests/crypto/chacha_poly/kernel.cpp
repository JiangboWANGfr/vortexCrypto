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
  template <int N> static inline uint32_t xr(uint32_t v, uint32_t w) {
    return rotl<N>(v ^ w);
  }
};

struct rot_hw {
  template <int N> static inline uint32_t rotl(uint32_t v) {
    return vx_rotl32(v, N);
  }
  // The quarter-round never rotates without xoring first, so the default is the
  // pair written out; the policy below fuses them into one instruction.
  template <int N> static inline uint32_t xr(uint32_t v, uint32_t w) {
    return vx_rotl32(v ^ w, N);
  }
};

#ifdef VX_CFG_EXT_SYM_CHACHA_ENABLE
// The one candidate ChaCha20 instruction: xor-then-rotate as a single op. It
// carries no S-box, no field arithmetic and no algorithm constant -- unlike the
// AES and GHASH extensions, ChaCha's software form is already add/xor/rotate,
// so the only thing left to fuse is the pair the quarter-round always performs
// together. Four of the twelve instructions per quarter-round go away.
struct rot_xr {
  template <int N> static inline uint32_t rotl(uint32_t v) {
    return vx_rotl32(v, N);
  }
  template <int N> static inline uint32_t xr(uint32_t v, uint32_t w) {
    return vx_chacha32_xr(v, w, N);
  }
};
#endif

// RFC 8439 section 2.1. Four adds, four xors and four rotates.
template <typename R>
__attribute__((always_inline)) inline void quarter_round(uint32_t x[16], int a, int b, int c, int d) {
  x[a] += x[b]; x[d] = R::template xr<16>(x[d], x[a]);
  x[c] += x[d]; x[b] = R::template xr<12>(x[b], x[c]);
  x[a] += x[b]; x[d] = R::template xr<8>(x[d], x[a]);
  x[c] += x[d]; x[b] = R::template xr<7>(x[b], x[c]);
}

// RFC 8439 section 2.3. The permutation alone, leaving the sixteen keystream words in x[]. Split out
// so that the two callers can consume x[] differently without the rounds being
// written twice: the once-per-message Poly1305 key wants the raw words, the
// per-block path wants them XORed and gone.
template <typename R, int PERM>
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
    if (PERM == 1) {
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
    } else if (PERM == 2) {
      // Diagonal round reversed, column round left alone. The four diagonal
      // quarter-rounds touch {0,5,10,15}, {1,6,11,12}, {2,7,8,13}, {3,4,9,14},
      // which are disjoint, so this is bit-identical for the same reason.
      quarter_round<R>(x, 0, 4, 8, 12);
      quarter_round<R>(x, 1, 5, 9, 13);
      quarter_round<R>(x, 2, 6, 10, 14);
      quarter_round<R>(x, 3, 7, 11, 15);
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
template <int PERM = 0, int POLY = 0>
__attribute__((always_inline)) inline void poly1305_block(poly1305_t& st, uint32_t t0, uint32_t t1,
                           uint32_t t2, uint32_t t3) {
  uint32_t h0 = st.h0 + (t0 & 0x3ffffff);
  uint32_t h1 = st.h1 + (((t0 >> 26) | (t1 << 6)) & 0x3ffffff);
  uint32_t h2 = st.h2 + (((t1 >> 20) | (t2 << 12)) & 0x3ffffff);
  uint32_t h3 = st.h3 + (((t2 >> 14) | (t3 << 18)) & 0x3ffffff);
  uint32_t h4 = st.h4 + ((t3 >> 8) | (1u << 24)); // the appended 0x01 byte

  // PERM == 3 computes these five in reverse. Each reads h0..h4 and the r and
  // s limbs and writes only its own d, so they are independent and the order is
  // bit-identical -- a probe in a different region from the quarter-round
  // reorderings, with a different liveness pattern and integer multiplies
  // rather than ARX.
  uint64_t d0, d1, d2, d3, d4;
  if (PERM == 3) {
    d4 = (uint64_t)h0 * st.r4 + (uint64_t)h1 * st.r3
       + (uint64_t)h2 * st.r2 + (uint64_t)h3 * st.r1
       + (uint64_t)h4 * st.r0;
    d3 = (uint64_t)h0 * st.r3 + (uint64_t)h1 * st.r2
       + (uint64_t)h2 * st.r1 + (uint64_t)h3 * st.r0
       + (uint64_t)h4 * st.s4;
    d2 = (uint64_t)h0 * st.r2 + (uint64_t)h1 * st.r1
       + (uint64_t)h2 * st.r0 + (uint64_t)h3 * st.s4
       + (uint64_t)h4 * st.s3;
    d1 = (uint64_t)h0 * st.r1 + (uint64_t)h1 * st.r0
       + (uint64_t)h2 * st.s4 + (uint64_t)h3 * st.s3
       + (uint64_t)h4 * st.s2;
    d0 = (uint64_t)h0 * st.r0 + (uint64_t)h1 * st.s4
       + (uint64_t)h2 * st.s3 + (uint64_t)h3 * st.s2
       + (uint64_t)h4 * st.s1;
  } else {
    d0 = (uint64_t)h0 * st.r0 + (uint64_t)h1 * st.s4
       + (uint64_t)h2 * st.s3 + (uint64_t)h3 * st.s2
       + (uint64_t)h4 * st.s1;
    d1 = (uint64_t)h0 * st.r1 + (uint64_t)h1 * st.r0
       + (uint64_t)h2 * st.s4 + (uint64_t)h3 * st.s3
       + (uint64_t)h4 * st.s2;
    d2 = (uint64_t)h0 * st.r2 + (uint64_t)h1 * st.r1
       + (uint64_t)h2 * st.r0 + (uint64_t)h3 * st.s4
       + (uint64_t)h4 * st.s3;
    d3 = (uint64_t)h0 * st.r3 + (uint64_t)h1 * st.r2
       + (uint64_t)h2 * st.r1 + (uint64_t)h3 * st.r0
       + (uint64_t)h4 * st.s4;
    d4 = (uint64_t)h0 * st.r4 + (uint64_t)h1 * st.r3
       + (uint64_t)h2 * st.r2 + (uint64_t)h3 * st.r1
       + (uint64_t)h4 * st.r0;
  }

  if (POLY == 1) {
#ifdef VX_CFG_EXT_AUTH_POLY_ENABLE
    // The same 5x5 convolution, accumulated as separate low and high halves so
    // that everything stays in 32-bit registers. The wrapped terms take the *5
    // forms and read r directly, so s1..s4 are never needed -- four fewer live
    // values in a kernel that already spills.
    uint32_t l0 = 0, l1 = 0, l2 = 0, l3 = 0, l4 = 0;
    uint32_t u0 = 0, u1 = 0, u2 = 0, u3 = 0, u4 = 0;

    l0 = vx_poly26_macl (l0, h0, st.r0); u0 = vx_poly26_mach (u0, h0, st.r0);
    l0 = vx_poly26_macl5(l0, h1, st.r4); u0 = vx_poly26_mach5(u0, h1, st.r4);
    l0 = vx_poly26_macl5(l0, h2, st.r3); u0 = vx_poly26_mach5(u0, h2, st.r3);
    l0 = vx_poly26_macl5(l0, h3, st.r2); u0 = vx_poly26_mach5(u0, h3, st.r2);
    l0 = vx_poly26_macl5(l0, h4, st.r1); u0 = vx_poly26_mach5(u0, h4, st.r1);

    l1 = vx_poly26_macl (l1, h0, st.r1); u1 = vx_poly26_mach (u1, h0, st.r1);
    l1 = vx_poly26_macl (l1, h1, st.r0); u1 = vx_poly26_mach (u1, h1, st.r0);
    l1 = vx_poly26_macl5(l1, h2, st.r4); u1 = vx_poly26_mach5(u1, h2, st.r4);
    l1 = vx_poly26_macl5(l1, h3, st.r3); u1 = vx_poly26_mach5(u1, h3, st.r3);
    l1 = vx_poly26_macl5(l1, h4, st.r2); u1 = vx_poly26_mach5(u1, h4, st.r2);

    l2 = vx_poly26_macl (l2, h0, st.r2); u2 = vx_poly26_mach (u2, h0, st.r2);
    l2 = vx_poly26_macl (l2, h1, st.r1); u2 = vx_poly26_mach (u2, h1, st.r1);
    l2 = vx_poly26_macl (l2, h2, st.r0); u2 = vx_poly26_mach (u2, h2, st.r0);
    l2 = vx_poly26_macl5(l2, h3, st.r4); u2 = vx_poly26_mach5(u2, h3, st.r4);
    l2 = vx_poly26_macl5(l2, h4, st.r3); u2 = vx_poly26_mach5(u2, h4, st.r3);

    l3 = vx_poly26_macl (l3, h0, st.r3); u3 = vx_poly26_mach (u3, h0, st.r3);
    l3 = vx_poly26_macl (l3, h1, st.r2); u3 = vx_poly26_mach (u3, h1, st.r2);
    l3 = vx_poly26_macl (l3, h2, st.r1); u3 = vx_poly26_mach (u3, h2, st.r1);
    l3 = vx_poly26_macl (l3, h3, st.r0); u3 = vx_poly26_mach (u3, h3, st.r0);
    l3 = vx_poly26_macl5(l3, h4, st.r4); u3 = vx_poly26_mach5(u3, h4, st.r4);

    l4 = vx_poly26_macl (l4, h0, st.r4); u4 = vx_poly26_mach (u4, h0, st.r4);
    l4 = vx_poly26_macl (l4, h1, st.r3); u4 = vx_poly26_mach (u4, h1, st.r3);
    l4 = vx_poly26_macl (l4, h2, st.r2); u4 = vx_poly26_mach (u4, h2, st.r2);
    l4 = vx_poly26_macl (l4, h3, st.r1); u4 = vx_poly26_mach (u4, h3, st.r1);
    l4 = vx_poly26_macl (l4, h4, st.r0); u4 = vx_poly26_mach (u4, h4, st.r0);

    // d_i = l_i + 2^26 * u_i, so the limb is l_i mod 2^26 and the carry out is
    // (l_i >> 26) + u_i. Every intermediate stays under 2^31.
    uint32_t cc;
    h0 = l0 & 0x3ffffff; cc = (l0 >> 26) + u0;
    l1 += cc; h1 = l1 & 0x3ffffff; cc = (l1 >> 26) + u1;
    l2 += cc; h2 = l2 & 0x3ffffff; cc = (l2 >> 26) + u2;
    l3 += cc; h3 = l3 & 0x3ffffff; cc = (l3 >> 26) + u3;
    l4 += cc; h4 = l4 & 0x3ffffff; cc = (l4 >> 26) + u4;
    h0 += cc * 5; cc = h0 >> 26; h0 &= 0x3ffffff;
    h1 += cc;
    st.h0 = h0; st.h1 = h1; st.h2 = h2; st.h3 = h3; st.h4 = h4;
    return;
#endif
  }

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
template <typename R, int PERM, int POLY = 0>
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
    poly1305_block<PERM, POLY>(st, c0, c1, c2, c3);
  }
}

// Poly1305 with the accumulator in five 26-bit limbs, so a 26x26 product fits
// a 32x32 multiply and the carries out of five of them still fit 64 bits.
// RV32 has no multiply-accumulate, so each partial product is a mul/mulhu
// pair; that is the cost the S1 work has to beat.
template <typename R, int PERM = 0, int POLY = 0>
inline void chacha_poly_body(kernel_arg_t* __UNIFORM__ arg) {
  const uint32_t* key = (const uint32_t*)arg->key_addr;
  const uint8_t* nonce_base = (const uint8_t*)arg->nonce_addr;
  const uint32_t* src_base = (const uint32_t*)arg->src_addr;
  uint32_t* dst_base = (uint32_t*)arg->dst_addr;
  uint32_t* tag_base = (uint32_t*)arg->tag_addr;

  const uint32_t num_msgs = arg->num_msgs;
  const uint32_t blocks = arg->blocks_per_msg;
  const uint32_t tail = arg->tail_bytes;
  const uint32_t aad_bytes = arg->aad_bytes;
  const uint8_t* aad = (const uint8_t*)arg->aad_addr;
  const uint32_t msg_bytes = CHACHA_BLOCK_BYTES * blocks + tail;
  // Buffer stride is the message length rounded UP to a whole ChaCha20 block,
  // deliberately not the message length: the word-wise streaming path below is
  // only valid while each message base is 4-byte aligned, and RISC-V traps on
  // an unaligned word access rather than fixing it up. The padding bytes are
  // never read and never authenticated -- msg_bytes is what the AEAD sees.
  const uint32_t words =
      (blocks + (tail != 0u ? 1u : 0u)) * (CHACHA_BLOCK_BYTES / 4);

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

    // AAD, absorbed before any ciphertext and never encrypted (RFC 8439
    // section 2.8). pad16 zero-fills the final chunk to a whole Poly1305 block,
    // so every chunk enters as a full block and the 0x01 byte stays at position
    // 16 -- there is no Poly1305 partial block anywhere in this AEAD. Byte-wise
    // because the AAD length is arbitrary and its base carries no alignment
    // guarantee; it runs once per message, not once per block.
    for (uint32_t off = 0; off < aad_bytes; off += POLY1305_BLOCK_BYTES) {
      const uint32_t n = (aad_bytes - off < POLY1305_BLOCK_BYTES)
                       ? (aad_bytes - off) : POLY1305_BLOCK_BYTES;
      uint8_t padded[POLY1305_BLOCK_BYTES] = {0};
      for (uint32_t i = 0; i < n; ++i) {
        padded[i] = aad[off + i];
      }
      poly1305_block<PERM, POLY>(st, load_le32(padded), load_le32(padded + 4),
                           load_le32(padded + 8), load_le32(padded + 12));
    }

    const uint32_t* pt = src_base + (size_t)words * msg;
    uint32_t* ct = dst_base + (size_t)words * msg;
    for (uint32_t b = 0; b < blocks; ++b) {
      chacha20_xor_absorb<R, PERM, POLY>(k, n0, n1, n2, b + 1, pt + 16 * b,
                                   ct + 16 * b, st);
    }

    // Partial final block: `tail` bytes of keystream consumed, the ciphertext
    // fragment zero-padded to whole Poly1305 blocks before they are absorbed.
    // Byte-wise on purpose -- the word-wise path above is justified by 64-byte
    // alignment, which a tail by definition does not have, and a word store
    // here would write up to three bytes past the message.
    if (tail != 0) {
      uint32_t x[16];
      chacha20_keystream<R, PERM>(k, n0, n1, n2, blocks + 1, x);
      const uint8_t* pb = (const uint8_t*)(pt + 16 * blocks);
      uint8_t* cb = (uint8_t*)(ct + 16 * blocks);
      for (uint32_t off = 0; off < tail; off += POLY1305_BLOCK_BYTES) {
        const uint32_t n = (tail - off < POLY1305_BLOCK_BYTES)
                         ? (tail - off) : POLY1305_BLOCK_BYTES;
        uint8_t padded[POLY1305_BLOCK_BYTES] = {0};
        for (uint32_t i = 0; i < n; ++i) {
          const uint32_t j = off + i;
          const uint8_t ksb = (uint8_t)(x[j >> 2] >> (8 * (j & 3)));
          const uint8_t c = (uint8_t)(pb[j] ^ ksb);
          cb[j] = c;
          padded[i] = c;
        }
        poly1305_block<PERM, POLY>(st, load_le32(padded), load_le32(padded + 4),
                             load_le32(padded + 8), load_le32(padded + 12));
      }
    }

    // The trailer: le64(AAD bytes) || le64(ciphertext bytes).
    const uint64_t aad_len = (uint64_t)aad_bytes;
    const uint64_t ct_bytes = (uint64_t)msg_bytes;
    poly1305_block<PERM, POLY>(st, (uint32_t)aad_len, (uint32_t)(aad_len >> 32),
                         (uint32_t)ct_bytes, (uint32_t)(ct_bytes >> 32));

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
  chacha_poly_body<rot_sw, 0>(arg);
}

// Bit-identical to chacha_poly_sw. Its only purpose is to measure the distance
// between two kernels that cannot differ, which is the floor below which a
// result from this application is not legible.
//
// The probe has a validity condition and it must be checked on every use: the
// entry points must differ by a SMALL FIXED number of instructions that does
// not grow with the block count. Absolute, not proportional -- a valid probe
// perturbs the count by a constant, so a percentage threshold rejects it at
// small problem sizes and accepts a scaling perturbation at large ones. These
// differ by exactly 4 instructions at every size from -b4 to -b64.
//
// Semantic equivalence does not imply instruction identity, and the failures
// are not subtle. In this same family, reordering an XOR accumulation that is
// bit-identical by associativity moved the count 1.24%; reversing four
// independent statement groups moved it 0.24%; reversing a loop moved it 2.9%
// and would have reported a 66% floor. A probe that fails silently is worse
// than no probe, because it fails toward ending the inquiry.
//
// The floor is also specific to a configuration and an application, not a
// property of the machine: the equivalent probe on aes_gcm measures 0.3% at
// c1w16t4 and 2.9% at c1w4t32. Measure it where the result is quoted.
__kernel void chacha_poly_sw_perm(kernel_arg_t* __UNIFORM__ arg) {
  chacha_poly_body<rot_sw, 1>(arg);
}

// REJECTED AS AN INSTRUMENT -- kept so the rejection is not rediscovered.
// Arithmetically bit-identical and it computes the correct AEAD, but the
// compiler does not agree: the instruction count moves +28 at -b4 and +124 at
// -b16, so the perturbation SCALES with the workload and its cycle delta is a
// real code difference rather than a floor reading. Do not quote its numbers.
__kernel void chacha_poly_sw_perm2(kernel_arg_t* __UNIFORM__ arg) {
  chacha_poly_body<rot_sw, 2>(arg);
}

// ALSO REJECTED. This was the one that mattered: a different region from the
// quarter-rounds, integer multiplies rather than ARX, a different liveness
// pattern -- the probe that would have said whether the tight floor belongs to
// this application or only to the disjoint-quarter-round structure. It computes
// the correct AEAD and is bit-identical by construction, and the compiler still
// emits +340 instructions at -b4 and +292 at -b16. Do not quote its numbers.
//
// So the question it was built to answer remains open, and the reason is worth
// stating: three of the four perturbations tried here are arithmetically
// bit-identical and only one produces a comparable instruction stream.
// Bit-identical by construction is NECESSARY for a floor probe and nowhere near
// sufficient; the compiler has to agree, and usually it does not.
__kernel void chacha_poly_sw_perm3(kernel_arg_t* __UNIFORM__ arg) {
  chacha_poly_body<rot_sw, 3>(arg);
}

// Same code with RORI. This is not a cryptographic instruction, so this row is
// a stronger software baseline rather than an instruction-set extension --
// see sw/kernel/include/crypto/vx_chacha.h.
__kernel void chacha_poly_rori(kernel_arg_t* __UNIFORM__ arg) {
  chacha_poly_body<rot_hw, 0>(arg);
}

#ifdef VX_CFG_EXT_AUTH_POLY_ENABLE
// Poly1305's 5x5 convolution as three-source multiply-accumulates. The ChaCha20
// half is untouched, so the difference against the sw row is the authenticator
// and nothing else.
__kernel void chacha_poly_mac(kernel_arg_t* __UNIFORM__ arg) {
  chacha_poly_body<rot_sw, 0, 1>(arg);
}
#endif

#if defined(VX_CFG_EXT_SYM_CHACHA_ENABLE) && defined(VX_CFG_EXT_AUTH_POLY_ENABLE)
// Both halves: the fused xor-rotate for ChaCha20 and the MAC for Poly1305.
// This is the complete S1 row for this AEAD.
__kernel void chacha_poly_s1(kernel_arg_t* __UNIFORM__ arg) {
  chacha_poly_body<rot_xr, 0, 1>(arg);
}
#endif

#ifdef VX_CFG_EXT_SYM_CHACHA_ENABLE
// The same kernel with the xor and the rotate fused. Everything else -- the
// layout, the Poly1305 path, the message-to-lane mapping -- is identical to the
// rori row, so the difference between them is the fusion and nothing else.
__kernel void chacha_poly_xr(kernel_arg_t* __UNIFORM__ arg) {
  chacha_poly_body<rot_xr, 0>(arg);
}
#endif
