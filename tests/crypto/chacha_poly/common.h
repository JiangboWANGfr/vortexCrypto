#ifndef _COMMON_H_
#define _COMMON_H_

// ChaCha20-Poly1305 AEAD (RFC 8439), one independent message per thread,
// empty AAD. Every message shares the 256-bit key; each has its own 96-bit
// nonce.
//
// Three things differ from tests/crypto/aes_gcm, and all three are forced by
// the algorithm rather than chosen:
//
//  - There are no tables. ChaCha20 is ARX over sixteen 32-bit words and
//    Poly1305 is integer arithmetic modulo 2^130-5, so nothing is looked up
//    and the kernel asks for no local memory. The whole argument for filling
//    LMEM in aes_gcm -- that a table lookup is a data-dependent gather across
//    the SIMD width -- has no counterpart here.
//  - There is no key schedule, so the host has nothing to precompute and the
//    "key expansion is host-side" policy has nothing to apply to.
//  - The Poly1305 one-time key depends on the nonce, so it is per message and
//    must be derived on the device: one extra ChaCha20 block per message.
//    GHASH's H depends only on the key, which is why aes_gcm can upload it.
//
// The launch geometry is kept identical to aes_gcm (one persistent CTA per
// core, grid-stride over messages) so that the two applications differ in
// their device code and not in how they are dispatched.

#define CHACHA_BLOCK_BYTES   64
#define CHACHA_KEY_BYTES     32
#define CHACHA_NONCE_BYTES   12
#define CHACHA_ROUNDS        20
#define POLY1305_BLOCK_BYTES 16
#define POLY1305_TAG_BYTES   16

typedef struct {
  uint32_t num_msgs;
  uint32_t blocks_per_msg; // 64-byte ChaCha20 blocks
  uint64_t key_addr;
  uint64_t nonce_addr;
  uint64_t src_addr;
  uint64_t dst_addr;
  uint64_t tag_addr;
} kernel_arg_t;

#endif
