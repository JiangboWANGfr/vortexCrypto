#ifndef _CHACHA_POLY_REF_H_
#define _CHACHA_POLY_REF_H_

// Host-side ChaCha20-Poly1305 reference, written straight from RFC 8439 so it
// can act as the oracle for the device kernel.
//
// Poly1305 is deliberately the slow, obvious formulation: the accumulator is
// an explicit bignum in 32-bit limbs and the reduction modulo 2^130-5 folds
// everything above bit 130 back with a factor of five until nothing is left.
// The device uses the packed 26-bit limb form, where carries are deferred
// across five limbs, so a disagreement points at the packing rather than at a
// shared misreading of the spec.
//
// ChaCha20 has no such second formulation -- there is only one way to write
// it -- so its oracle value comes from the published vectors themselves
// (RFC 8439 sections 2.3.2 and 2.4.2), which main.cpp checks first.

#include <cstdint>
#include <cstring>
#include <vector>

namespace chacha_poly_ref {

inline uint32_t load_le32(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
       | ((uint32_t)p[3] << 24);
}

inline void store_le32(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

inline void store_le64(uint8_t* p, uint64_t v) {
  store_le32(p, (uint32_t)v);
  store_le32(p + 4, (uint32_t)(v >> 32));
}

inline uint32_t rotl32(uint32_t v, int n) {
  return (uint32_t)((v << n) | (v >> (32 - n)));
}

// RFC 8439 section 2.1.
inline void quarter_round(uint32_t x[16], int a, int b, int c, int d) {
  x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl32(x[d], 16);
  x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl32(x[b], 12);
  x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl32(x[d], 8);
  x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl32(x[b], 7);
}

// RFC 8439 section 2.3: twenty rounds over the sixteen-word state, then the
// original state added back in.
inline void chacha20_block(const uint8_t key[CHACHA_KEY_BYTES],
                           const uint8_t nonce[CHACHA_NONCE_BYTES],
                           uint32_t counter, uint8_t out[CHACHA_BLOCK_BYTES]) {
  uint32_t s[16];
  s[0] = 0x61707865; s[1] = 0x3320646e;
  s[2] = 0x79622d32; s[3] = 0x6b206574;
  for (int i = 0; i < 8; ++i) {
    s[4 + i] = load_le32(key + 4 * i);
  }
  s[12] = counter;
  for (int i = 0; i < 3; ++i) {
    s[13 + i] = load_le32(nonce + 4 * i);
  }

  uint32_t x[16];
  std::memcpy(x, s, sizeof(s));
  for (int i = 0; i < CHACHA_ROUNDS / 2; ++i) {
    quarter_round(x, 0, 4, 8, 12);
    quarter_round(x, 1, 5, 9, 13);
    quarter_round(x, 2, 6, 10, 14);
    quarter_round(x, 3, 7, 11, 15);
    quarter_round(x, 0, 5, 10, 15);
    quarter_round(x, 1, 6, 11, 12);
    quarter_round(x, 2, 7, 8, 13);
    quarter_round(x, 3, 4, 9, 14);
  }
  for (int i = 0; i < 16; ++i) {
    store_le32(out + 4 * i, x[i] + s[i]);
  }
}

// RFC 8439 section 2.4.
inline void chacha20_xor(const uint8_t key[CHACHA_KEY_BYTES],
                         const uint8_t nonce[CHACHA_NONCE_BYTES],
                         uint32_t counter, const uint8_t* in, size_t len,
                         uint8_t* out) {
  uint8_t ks[CHACHA_BLOCK_BYTES];
  for (size_t off = 0; off < len; off += CHACHA_BLOCK_BYTES) {
    chacha20_block(key, nonce, counter + (uint32_t)(off / CHACHA_BLOCK_BYTES),
                   ks);
    const size_t n = (len - off < CHACHA_BLOCK_BYTES) ? (len - off)
                                                      : CHACHA_BLOCK_BYTES;
    for (size_t i = 0; i < n; ++i) {
      out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
    }
  }
}

// RFC 8439 section 2.5. h and the product are carried in 32-bit limbs, least
// significant first; h stays below 2^130 between blocks, so five limbs hold it.
inline void poly1305_mac(const uint8_t key[32], const uint8_t* msg, size_t len,
                         uint8_t tag[POLY1305_TAG_BYTES]) {
  uint8_t rb[16];
  std::memcpy(rb, key, 16);
  rb[3] &= 15; rb[7] &= 15; rb[11] &= 15; rb[15] &= 15;
  rb[4] &= 252; rb[8] &= 252; rb[12] &= 252;

  uint32_t r[4];
  for (int i = 0; i < 4; ++i) {
    r[i] = load_le32(rb + 4 * i);
  }

  uint32_t h[5] = {0, 0, 0, 0, 0};
  for (size_t off = 0; off < len; off += POLY1305_BLOCK_BYTES) {
    const size_t n = (len - off < POLY1305_BLOCK_BYTES)
                   ? (len - off) : POLY1305_BLOCK_BYTES;
    // Every block, full or not, has a 0x01 byte appended before it is read as
    // a little-endian number.
    uint8_t blk[POLY1305_BLOCK_BYTES + 1] = {0};
    std::memcpy(blk, msg + off, n);
    blk[n] = 1;

    uint64_t carry = 0;
    for (int i = 0; i < 5; ++i) {
      const uint32_t b = (i < 4) ? load_le32(blk + 4 * i) : (uint32_t)blk[16];
      const uint64_t t = (uint64_t)h[i] + b + carry;
      h[i] = (uint32_t)t;
      carry = t >> 32;
    }

    // h *= r, schoolbook, five limbs by four.
    uint32_t p[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    for (int i = 0; i < 5; ++i) {
      uint64_t c = 0;
      for (int j = 0; j < 4; ++j) {
        const uint64_t t = (uint64_t)h[i] * r[j] + p[i + j] + c;
        p[i + j] = (uint32_t)t;
        c = t >> 32;
      }
      for (int j = 4; c != 0 && i + j < 9; ++j) {
        const uint64_t t = (uint64_t)p[i + j] + c;
        p[i + j] = (uint32_t)t;
        c = t >> 32;
      }
    }

    // p mod (2^130-5): 2^130 == 5, so the part above bit 130 comes back
    // multiplied by five. Folding grows nothing, so it terminates.
    for (;;) {
      uint32_t hi[9];
      bool any = false;
      for (int i = 0; i < 9; ++i) {
        uint32_t v = (i + 4 < 9) ? (p[i + 4] >> 2) : 0u;
        if (i + 5 < 9) {
          v |= (uint32_t)(p[i + 5] << 30);
        }
        hi[i] = v;
        any = any || (v != 0);
      }
      p[4] &= 3;
      for (int i = 5; i < 9; ++i) {
        p[i] = 0;
      }
      if (!any) {
        break;
      }
      uint64_t c = 0;
      for (int i = 0; i < 9; ++i) {
        const uint64_t t = (uint64_t)p[i] + (uint64_t)hi[i] * 5 + c;
        p[i] = (uint32_t)t;
        c = t >> 32;
      }
    }
    for (int i = 0; i < 5; ++i) {
      h[i] = p[i];
    }
  }

  // h is below 2^130 but may still be at least 2^130-5, so subtract once.
  uint32_t g[5];
  uint64_t c = 5;
  for (int i = 0; i < 5; ++i) {
    const uint64_t t = (uint64_t)h[i] + c;
    g[i] = (uint32_t)t;
    c = t >> 32;
  }
  if ((g[4] >> 2) != 0) { // h + 5 reached bit 130, so h >= 2^130-5
    for (int i = 0; i < 4; ++i) {
      h[i] = g[i];
    }
    h[4] = g[4] & 3;
  }

  // tag = (h + s) mod 2^128
  uint64_t f = 0;
  for (int i = 0; i < 4; ++i) {
    f = (uint64_t)h[i] + load_le32(key + 16 + 4 * i) + (f >> 32);
    store_le32(tag + 4 * i, (uint32_t)f);
  }
}

// RFC 8439 section 2.8. The Poly1305 key is the first 32 bytes of the
// keystream at counter zero; the payload starts at counter one.
inline void aead_encrypt(const uint8_t key[CHACHA_KEY_BYTES],
                         const uint8_t nonce[CHACHA_NONCE_BYTES],
                         const uint8_t* aad, size_t aad_len,
                         const uint8_t* pt, size_t pt_len, uint8_t* ct,
                         uint8_t tag[POLY1305_TAG_BYTES]) {
  uint8_t block0[CHACHA_BLOCK_BYTES];
  chacha20_block(key, nonce, 0, block0);
  chacha20_xor(key, nonce, 1, pt, pt_len, ct);

  std::vector<uint8_t> mac_data;
  if (aad_len != 0) {
    mac_data.insert(mac_data.end(), aad, aad + aad_len);
  }
  mac_data.resize((mac_data.size() + 15) & ~(size_t)15, 0);
  mac_data.insert(mac_data.end(), ct, ct + pt_len);
  mac_data.resize((mac_data.size() + 15) & ~(size_t)15, 0);
  uint8_t lens[16];
  store_le64(lens, (uint64_t)aad_len);
  store_le64(lens + 8, (uint64_t)pt_len);
  mac_data.insert(mac_data.end(), lens, lens + 16);

  poly1305_mac(block0, mac_data.data(), mac_data.size(), tag);
}

} // namespace chacha_poly_ref

#endif
