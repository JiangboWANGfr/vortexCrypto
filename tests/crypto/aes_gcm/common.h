#ifndef _COMMON_H_
#define _COMMON_H_

// AES-128-GCM, one independent message per thread, empty AAD.
// Every message shares the key schedule, the T-tables and the GHASH table;
// each has its own 96-bit IV. The device copies the three shared tables into
// local memory once per CTA, so a data-dependent table lookup lands on the
// 32-bank LMEM rather than the single-bank D-cache.

#define AES_BLOCK_BYTES 16
#define AES128_ROUNDS   10
#define AES128_RK_BYTES ((AES128_ROUNDS + 1) * AES_BLOCK_BYTES)
#define GCM_IV_BYTES    12
#define GCM_TAG_BYTES   16

// Four 1 KB T-tables, byte-rotations of each other.
#define AES_TE_ENTRIES  256
#define AES_TE_TABLES   4
#define AES_TE_BYTES    (AES_TE_TABLES * AES_TE_ENTRIES * 4)

// GHASH multiplies four bits of the operand per step, so the table holds
// i*H for i in 0..15.
#define GHASH_TABLE_ENTRIES 16
#define GHASH_TABLE_BYTES   (GHASH_TABLE_ENTRIES * AES_BLOCK_BYTES)

#define AES_GCM_LMEM_BYTES \
  (AES_TE_BYTES + AES128_RK_BYTES + GHASH_TABLE_BYTES)

typedef struct {
  uint32_t num_msgs;
  uint32_t blocks_per_msg;   // FULL 16-byte blocks
  // Trailing bytes after the full blocks, 0..15. GCM is defined over arbitrary
  // byte lengths (SP 800-38D 7.1); without this the ABI can only express
  // multiples of 16, and the only way to attempt a short message would be to
  // round the block count up and pass a shorter buffer -- which nothing here
  // would reject. Message length is 16 * blocks_per_msg + tail_bytes.
  uint32_t tail_bytes;
  uint64_t rk_addr;
  uint64_t te_addr;
  uint64_t htable_addr;
  // The hash subkey H = AES_K(0^128) as 16 raw bytes, used by the clmul GHASH.
  // It cannot be recovered from htable: entry i there is (i << 4)·H, a nibble
  // selector, not i·H. Host-provided for the same reason the key schedule is --
  // a variant deriving it on-device would be measured against one that doesn't.
  uint64_t h_addr;
  uint64_t iv_addr;
  uint64_t src_addr;
  uint64_t dst_addr;
  uint64_t tag_addr;
} kernel_arg_t;

#endif
