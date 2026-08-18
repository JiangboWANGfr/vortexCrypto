#ifndef _AES_GCM_REF_H_
#define _AES_GCM_REF_H_

// Host-side AES-128-GCM reference, written straight from the specifications
// so it can act as the oracle for the device kernel. It is deliberately the
// slow, obvious formulation: byte-oriented AES (FIPS-197) and a bit-at-a-time
// GF(2^128) multiply (SP 800-38D Algorithm 1). The device uses table-driven
// forms of both, so a disagreement points at the tables rather than at a
// shared misreading of the spec.

#include <cstdint>
#include <cstring>

namespace aes_gcm_ref {

static const uint8_t kSbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

inline uint8_t xtime(uint8_t a) {
  return (uint8_t)((a << 1) ^ ((a >> 7) * 0x1b));
}

// FIPS-197 section 5.2, AES-128: 11 round keys of 16 bytes.
inline void key_expand(const uint8_t key[16], uint8_t rk[AES128_RK_BYTES]) {
  std::memcpy(rk, key, 16);
  uint8_t rcon = 1;
  for (int i = 16; i < AES128_RK_BYTES; i += 4) {
    uint8_t t[4];
    std::memcpy(t, rk + i - 4, 4);
    if ((i % 16) == 0) {
      const uint8_t rot = t[0];
      t[0] = (uint8_t)(kSbox[t[1]] ^ rcon);
      t[1] = kSbox[t[2]];
      t[2] = kSbox[t[3]];
      t[3] = kSbox[rot];
      rcon = xtime(rcon);
    }
    for (int j = 0; j < 4; ++j) {
      rk[i + j] = (uint8_t)(rk[i - 16 + j] ^ t[j]);
    }
  }
}

// FIPS-197 section 5.1.
inline void encrypt_block(const uint8_t rk[AES128_RK_BYTES],
                          const uint8_t in[16], uint8_t out[16]) {
  uint8_t s[16];
  for (int i = 0; i < 16; ++i) {
    s[i] = (uint8_t)(in[i] ^ rk[i]);
  }
  for (int round = 1; round <= AES128_ROUNDS; ++round) {
    uint8_t t[16];
    for (int i = 0; i < 16; ++i) {
      t[i] = kSbox[s[i]];
    }
    // ShiftRows on the column-major state: byte r + 4c moves left by r columns.
    uint8_t r[16];
    for (int c = 0; c < 4; ++c) {
      for (int row = 0; row < 4; ++row) {
        r[4 * c + row] = t[4 * ((c + row) & 3) + row];
      }
    }
    if (round != AES128_ROUNDS) {
      for (int c = 0; c < 4; ++c) {
        uint8_t* p = r + 4 * c;
        const uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        const uint8_t x = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
        p[0] = (uint8_t)(a0 ^ x ^ xtime((uint8_t)(a0 ^ a1)));
        p[1] = (uint8_t)(a1 ^ x ^ xtime((uint8_t)(a1 ^ a2)));
        p[2] = (uint8_t)(a2 ^ x ^ xtime((uint8_t)(a2 ^ a3)));
        p[3] = (uint8_t)(a3 ^ x ^ xtime((uint8_t)(a3 ^ a0)));
      }
    }
    for (int i = 0; i < 16; ++i) {
      s[i] = (uint8_t)(r[i] ^ rk[16 * round + i]);
    }
  }
  std::memcpy(out, s, 16);
}

// SP 800-38D section 6.3, Algorithm 1: Z = X * Y in GF(2^128).
inline void gf_mul(const uint8_t x[16], const uint8_t y[16], uint8_t z[16]) {
  uint8_t v[16];
  uint8_t acc[16] = {0};
  std::memcpy(v, y, 16);
  for (int i = 0; i < 128; ++i) {
    if ((x[i >> 3] >> (7 - (i & 7))) & 1) {
      for (int j = 0; j < 16; ++j) {
        acc[j] ^= v[j];
      }
    }
    const int lsb = v[15] & 1;
    for (int j = 15; j > 0; --j) {
      v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
    }
    v[0] >>= 1;
    if (lsb) {
      v[0] ^= 0xe1;
    }
  }
  std::memcpy(z, acc, 16);
}

// Htable[i] = i * H, with i occupying the four most significant bits.
// Built with the bitwise multiply so the table itself is spec-derived.
inline void ghash_table(const uint8_t h[16],
                        uint8_t table[GHASH_TABLE_BYTES]) {
  for (int i = 0; i < GHASH_TABLE_ENTRIES; ++i) {
    uint8_t sel[16] = {0};
    sel[0] = (uint8_t)(i << 4);
    gf_mul(sel, h, table + 16 * i);
  }
}

inline void inc32(uint8_t ctr[16]) {
  for (int i = 15; i >= 12; --i) {
    if (++ctr[i] != 0) {
      break;
    }
  }
}

// AES-128-GCM encryption with an empty AAD and a 96-bit IV, over a whole
// number of blocks. SP 800-38D section 7.1.
inline void gcm_encrypt(const uint8_t rk[AES128_RK_BYTES],
                        const uint8_t h[16],
                        const uint8_t iv[GCM_IV_BYTES],
                        const uint8_t* pt, uint32_t blocks, uint32_t tail,
                        uint8_t* ct, uint8_t tag[GCM_TAG_BYTES]) {
  uint8_t j0[16];
  std::memcpy(j0, iv, GCM_IV_BYTES);
  j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;

  uint8_t ctr[16];
  std::memcpy(ctr, j0, 16);

  uint8_t y[16] = {0};
  for (uint32_t b = 0; b < blocks; ++b) {
    inc32(ctr);
    uint8_t ks[16];
    encrypt_block(rk, ctr, ks);
    for (int i = 0; i < 16; ++i) {
      ct[16 * b + i] = (uint8_t)(pt[16 * b + i] ^ ks[i]);
      y[i] ^= ct[16 * b + i];
    }
    uint8_t next[16];
    gf_mul(y, h, next);
    std::memcpy(y, next, 16);
  }

  // Partial final block, SP 800-38D section 7.1 step 4: only `tail` bytes of
  // keystream are consumed, and the ciphertext fragment is zero-padded to a
  // full block before GHASH absorbs it. Padding with anything else -- including
  // the surrounding plaintext -- changes the tag.
  if (tail != 0) {
    inc32(ctr);
    uint8_t ks[16];
    encrypt_block(rk, ctr, ks);
    uint8_t padded[16] = {0};
    for (uint32_t i = 0; i < tail; ++i) {
      ct[16 * blocks + i] = (uint8_t)(pt[16 * blocks + i] ^ ks[i]);
      padded[i] = ct[16 * blocks + i];
    }
    for (int i = 0; i < 16; ++i) {
      y[i] ^= padded[i];
    }
    uint8_t next[16];
    gf_mul(y, h, next);
    std::memcpy(y, next, 16);
  }

  // Length block: [len(A)]64 || [len(C)]64, in bits, big-endian. A is empty.
  uint8_t lenblk[16] = {0};
  const uint64_t cbits = ((uint64_t)blocks * 16u + tail) * 8u;
  for (int i = 0; i < 8; ++i) {
    lenblk[15 - i] = (uint8_t)(cbits >> (8 * i));
  }
  for (int i = 0; i < 16; ++i) {
    y[i] ^= lenblk[i];
  }
  uint8_t s[16];
  gf_mul(y, h, s);

  uint8_t ej0[16];
  encrypt_block(rk, j0, ej0);
  for (int i = 0; i < 16; ++i) {
    tag[i] = (uint8_t)(s[i] ^ ej0[i]);
  }
}

// The four T-tables the device uses, in the classic Rijndael convention:
// a state column is one big-endian word, and Te0[x] = [S(x)*2, S(x), S(x),
// S(x)*3] with S(x)*2 in the most significant byte. Te1..Te3 are Te0 rotated
// right by 8, 16 and 24 bits. The device recovers the plain S-box for the
// final round as (Te0[x] >> 16) & 0xff, so it needs no separate table.
inline void build_te(uint32_t te[AES_TE_TABLES * AES_TE_ENTRIES]) {
  for (int x = 0; x < AES_TE_ENTRIES; ++x) {
    const uint8_t s = kSbox[x];
    const uint8_t s2 = xtime(s);
    const uint8_t s3 = (uint8_t)(s2 ^ s);
    const uint32_t w = ((uint32_t)s2 << 24)
                     | ((uint32_t)s << 16)
                     | ((uint32_t)s << 8)
                     | (uint32_t)s3;
    te[x] = w;
    te[AES_TE_ENTRIES + x] = (w >> 8) | (w << 24);
    te[2 * AES_TE_ENTRIES + x] = (w >> 16) | (w << 16);
    te[3 * AES_TE_ENTRIES + x] = (w >> 24) | (w << 8);
  }
}

// Repack the byte-oriented round keys into big-endian column words so the
// device can add them straight into its word-sized state.
inline void rk_to_words(const uint8_t rk[AES128_RK_BYTES],
                        uint32_t words[AES128_RK_BYTES / 4]) {
  for (int i = 0; i < AES128_RK_BYTES / 4; ++i) {
    words[i] = ((uint32_t)rk[4 * i] << 24)
             | ((uint32_t)rk[4 * i + 1] << 16)
             | ((uint32_t)rk[4 * i + 2] << 8)
             | (uint32_t)rk[4 * i + 3];
  }
}

} // namespace aes_gcm_ref

#endif
