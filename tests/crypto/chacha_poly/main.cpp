#include <vortex2.h>
#include <VX_types.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <unistd.h>
#include "common.h"
#include "chacha_poly_ref.h"

#define CHECK(_expr)                                                  \
  do {                                                                \
    vx_result_t _r = (_expr);                                         \
    if (_r == VX_SUCCESS) {                                           \
      break;                                                          \
    }                                                                 \
    std::fprintf(stderr, "FAIL %s:%d: '%s' returned %s\n", __FILE__,  \
                 __LINE__, #_expr, vx_result_string(_r));             \
    std::exit(1);                                                     \
  } while (false)

namespace ref = chacha_poly_ref;

namespace {

const char* g_kernel_file = "kernel.vxbin";
uint32_t g_num_msgs = 256;
uint32_t g_blocks_per_msg = 4;
uint32_t g_tail_bytes = 0;
uint32_t g_aad_bytes = 0;
uint32_t g_impl = 0;

// Every implementation is a separate entry point in the same binary, sharing
// this host program's buffers, vectors and counter reduction. Only the device
// code differs, so a comparison between two rows measures the implementation
// and nothing else. Hardware-instruction variants join this table behind the
// extension guard that defines them.
struct impl_t {
  const char* kernel;
  const char* label;
  bool needs_sym;   // issues RORI, so requires EX_SYM
  bool needs_xr;    // issues chacha32.xr; needs VX_CFG_EXT_SYM_CHACHA_ENABLE
  bool needs_mac;   // issues poly26.mac*; needs VX_CFG_EXT_AUTH_POLY_ENABLE
  bool needs_quad;  // four lanes own one message, so num_msgs must divide by 4
  bool needs_sg4;   // needs VX_CFG_EXT_SYM_CHACHA_SG4_ENABLE and the poly twin
  bool needs_s2;    // needs VX_CFG_EXT_SYM_CHACHA_S2_ENABLE
};

const impl_t kImpls[] = {
  { "chacha_poly_sw",   "sw", false, false, false, false, false, false },
  // Same code with the ratified Zbb/Zbkb RORI in place of slli+srli+or. It is
  // not a cryptographic instruction, so this row is a stronger software
  // baseline, not an instruction-set extension: the ChaCha20 speedup it shows
  // is what any RV32 with the B extension already has.
  { "chacha_poly_rori", "rori", true, false, false, false, false, false },
  // Bit-identical to sw; see kernel.cpp. Measures the apparatus, not the cipher.
  { "chacha_poly_sw_perm", "sw_perm", false, false, false, false, false, false },
  // Rejected as instruments; see kernel.cpp. Correct, bit-identical by
  // construction, and the compiler emits a different instruction count anyway,
  // so their deltas are code differences rather than floor readings.
  { "chacha_poly_sw_perm2", "sw_perm2(rejected)", false, false, false, false, false, false },
  { "chacha_poly_sw_perm3", "sw_perm3(rejected)", false, false, false, false, false, false },
  // The one candidate ChaCha20 instruction: the quarter-round's xor and rotate
  // fused. Compared against the rori row rather than sw, because rori is the
  // honest baseline -- any RV32 with the B extension already has it.
  { "chacha_poly_xr",   "xr", true, true, false, false, false, false },
  // Poly1305's convolution as three-source MACs with ChaCha20 left alone, so
  // the delta against sw is the authenticator by itself.
  { "chacha_poly_mac",  "mac", false, false, true, false, false, false },
  // Both halves: the complete S1 row for this AEAD.
  { "chacha_poly_s1",   "s1", true, true, true, false, false, false },
  // S3 probe: a quad owns one message, so a warp carries four instead of
  // sixteen. Built from instructions that already exist, so it prices the
  // layout on its own -- what hw_s3 does for AES-GCM before aesrm.sg4 existed.
  { "chacha_poly_s3",   "s3", true, true, true, true, false, false },
  // The same layout with its cross-lane cost folded into the arithmetic.
  { "chacha_poly_s3f",  "s3f", true, true, true, true, true, false },
  // S2: one lane still owns one message, but ChaCha20's whole 512-bit state
  // moves into a per-lane context and one instruction is a double-round.
  { "chacha_poly_s2",   "s2", false, false, true, false, false, true },
};

const uint32_t kNumImpls = (uint32_t)(sizeof(kImpls) / sizeof(kImpls[0]));

// RFC 8439 section 2.3.2: the block function alone, at block counter one.
const uint8_t kBlockKey[CHACHA_KEY_BYTES] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
const uint8_t kBlockNonce[CHACHA_NONCE_BYTES] = {
  0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
  0x00, 0x00, 0x00, 0x00,
};
const uint8_t kBlockOut[CHACHA_BLOCK_BYTES] = {
  0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
  0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
  0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
  0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
  0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
  0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
  0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
  0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
};

// The 114-byte plaintext shared by RFC 8439 sections 2.4.2 and 2.8.2, kept as
// the hex of the RFC's own dump rather than retyped as a string literal.
const uint8_t kSunscreen[114] = {
  0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
  0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
  0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
  0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
  0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
  0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
  0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
  0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
  0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
  0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
  0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
  0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
  0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
  0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
  0x74, 0x2e,
};

// RFC 8439 section 2.4.2: encryption at initial counter one.
const uint8_t kStreamNonce[CHACHA_NONCE_BYTES] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
  0x00, 0x00, 0x00, 0x00,
};
const uint8_t kStreamCt[114] = {
  0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
  0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
  0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
  0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
  0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
  0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
  0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
  0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
  0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
  0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
  0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
  0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
  0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
  0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
  0x87, 0x4d,
};

// RFC 8439 section 2.5.2: Poly1305 on its own, over a 34-byte message, so the
// final partial block and the 0x01 padding byte are exercised even though the
// AEAD workload below only ever feeds whole blocks.
const uint8_t kPolyKey[32] = {
  0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
  0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
  0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
  0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
};
const uint8_t kPolyMsg[34] = {
  0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72,
  0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46, 0x6f,
  0x72, 0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65,
  0x61, 0x72, 0x63, 0x68, 0x20, 0x47, 0x72, 0x6f,
  0x75, 0x70,
};
const uint8_t kPolyTag[POLY1305_TAG_BYTES] = {
  0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
  0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
};

// RFC 8439 section 2.8.2: the whole AEAD, with a non-empty AAD. The nonce is
// the 32-bit fixed common part 07 00 00 00 followed by the 64-bit IV.
const uint8_t kAeadKey[CHACHA_KEY_BYTES] = {
  0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
  0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
  0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
};
const uint8_t kAeadNonce[CHACHA_NONCE_BYTES] = {
  0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
  0x44, 0x45, 0x46, 0x47,
};
const uint8_t kAeadAad[12] = {
  0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
  0xc4, 0xc5, 0xc6, 0xc7,
};
const uint8_t kAeadCt[114] = {
  0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
  0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
  0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
  0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
  0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
  0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
  0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
  0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
  0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
  0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
  0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
  0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
  0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
  0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
  0x61, 0x16,
};
const uint8_t kAeadTag[POLY1305_TAG_BYTES] = {
  0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
  0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
};

void show_usage() {
  std::printf(
      "ChaCha20-Poly1305\n"
      "Usage: [-n msgs] [-b blocks_per_msg] [-t tail_bytes] [-a aad_bytes] [-i impl] [-k kernel] [-h]\n"
      "  blocks are 64-byte ChaCha20 blocks\n");
  for (uint32_t i = 0; i < kNumImpls; ++i) {
    std::printf("  -i%u  %s\n", i, kImpls[i].label);
  }
}

void parse_args(int argc, char** argv) {
  int c;
  while ((c = getopt(argc, argv, "n:b:t:a:i:k:h")) != -1) {
    switch (c) {
    case 'n': g_num_msgs = (uint32_t)std::atoi(optarg); break;
    case 'b': g_blocks_per_msg = (uint32_t)std::atoi(optarg); break;
    case 't': g_tail_bytes = (uint32_t)std::atoi(optarg); break;
    case 'a': g_aad_bytes = (uint32_t)std::atoi(optarg); break;
    case 'i': g_impl = (uint32_t)std::atoi(optarg); break;
    case 'k': g_kernel_file = optarg; break;
    case 'h': show_usage(); std::exit(0); break;
    default: show_usage(); std::exit(-1);
    }
  }
}

int compare(const char* what, uint32_t msg, const uint8_t* got,
            const uint8_t* want, size_t n) {
  if (std::memcmp(got, want, n) == 0) {
    return 0;
  }
  std::printf("mismatch in %s of message %u\n", what, msg);
  for (size_t i = 0; i < n; ++i) {
    if (got[i] != want[i]) {
      std::printf("  byte %zu: device %02x, reference %02x\n", i, got[i],
                  want[i]);
    }
  }
  return 1;
}

// Level 1: the reference must reproduce the published vectors before it is
// allowed to judge the device.
int self_check_reference() {
  uint8_t block[CHACHA_BLOCK_BYTES];
  ref::chacha20_block(kBlockKey, kBlockNonce, 1, block);
  if (std::memcmp(block, kBlockOut, sizeof(kBlockOut)) != 0) {
    std::printf("reference block function does not match RFC 8439 2.3.2\n");
    return 1;
  }

  uint8_t stream[sizeof(kStreamCt)];
  ref::chacha20_xor(kBlockKey, kStreamNonce, 1, kSunscreen, sizeof(kSunscreen),
                    stream);
  if (std::memcmp(stream, kStreamCt, sizeof(kStreamCt)) != 0) {
    std::printf("reference ChaCha20 does not match RFC 8439 2.4.2\n");
    return 1;
  }

  uint8_t tag[POLY1305_TAG_BYTES];
  ref::poly1305_mac(kPolyKey, kPolyMsg, sizeof(kPolyMsg), tag);
  if (std::memcmp(tag, kPolyTag, sizeof(kPolyTag)) != 0) {
    std::printf("reference Poly1305 does not match RFC 8439 2.5.2\n");
    return 1;
  }

  uint8_t ct[sizeof(kAeadCt)];
  ref::aead_encrypt(kAeadKey, kAeadNonce, kAeadAad, sizeof(kAeadAad),
                    kSunscreen, sizeof(kSunscreen), ct, tag);
  if (std::memcmp(ct, kAeadCt, sizeof(kAeadCt)) != 0) {
    std::printf("reference AEAD ciphertext does not match RFC 8439 2.8.2\n");
    return 1;
  }
  if (std::memcmp(tag, kAeadTag, sizeof(kAeadTag)) != 0) {
    std::printf("reference AEAD tag does not match RFC 8439 2.8.2\n");
    return 1;
  }
  return 0;
}

} // namespace

int main(int argc, char** argv) {
  parse_args(argc, argv);
  if (g_impl >= kNumImpls) {
    std::printf("no such implementation: %u\n", g_impl);
    return 1;
  }

  if (self_check_reference() != 0) {
    std::printf("FAILED!\n");
    return 1;
  }
  std::printf("reference matches the RFC 8439 block, stream, Poly1305 and "
              "AEAD vectors\n");

  vx_device_h dev = nullptr;
  CHECK(vx_device_open(0, &dev));

  // Refuse rather than compute a wrong answer. RORI is an OP-IMM encoding and
  // the fallback decode path executes it as a shift -- SRAI in the RTL, SRL in
  // simx -- so without EX_SYM this kernel silently produces the wrong AEAD and
  // only the reference comparison notices, after the run. The hazard is
  // documented at the decode arm and was walked into anyway during bring-up, by
  // a CONFIGS string that omitted the enable. This turns it from documented
  // into impossible.
  if (kImpls[g_impl].needs_sym) {
    uint64_t isa_flags = 0;
    CHECK(vx_device_query(dev, VX_CAPS_ISA_FLAGS, &isa_flags));
    if ((isa_flags & VX_ISA_EXT_SYM) == 0) {
      std::printf("SKIPPED: impl '%s' issues RORI and needs EX_SYM, which this "
                  "device does not have. Rebuild with "
                  "CONFIGS=\"-DVX_CFG_EXT_SYM_ENABLE\".\n",
                  kImpls[g_impl].label);
      vx_device_release(dev);
      return 1;
    }
  }

  uint64_t num_cores = 0;
  uint64_t num_warps = 0;
  uint64_t num_threads = 0;
  CHECK(vx_device_query(dev, VX_CAPS_NUM_CORES, &num_cores));
  CHECK(vx_device_query(dev, VX_CAPS_NUM_WARPS, &num_warps));
  CHECK(vx_device_query(dev, VX_CAPS_NUM_THREADS, &num_threads));

  if (g_tail_bytes > CHACHA_BLOCK_BYTES - 1) {
    std::printf("FAILED: -t must be 0..63 (a tail is what is left after whole "
                "blocks); got %u\n", g_tail_bytes);
    return 1;
  }
  const uint32_t msg_bytes =
      CHACHA_BLOCK_BYTES * g_blocks_per_msg + g_tail_bytes;
  // Device buffers are strided by whole blocks so every message base stays
  // 4-byte aligned for the word-wise streaming path; only msg_bytes of each
  // slot carries data. Host-side reference buffers use the same stride so the
  // comparison is index-for-index.
  const uint32_t msg_stride =
      CHACHA_BLOCK_BYTES * (g_blocks_per_msg + (g_tail_bytes != 0 ? 1u : 0u));
  const size_t data_bytes = (size_t)msg_stride * g_num_msgs;

  std::printf("messages=%u blocks/msg=%u bytes=%zu cores=%lu warps=%lu "
              "threads=%lu\n",
              g_num_msgs, g_blocks_per_msg, data_bytes,
              (unsigned long)num_cores, (unsigned long)num_warps,
              (unsigned long)num_threads);

  // One key for every message, one nonce each. There is no key schedule to
  // expand, so unlike aes_gcm the host uploads the key itself.
  std::vector<uint8_t> h_nonce((size_t)CHACHA_NONCE_BYTES * g_num_msgs);
  std::vector<uint8_t> h_pt(data_bytes);
  // AAD is shared by every message: the TLS/IPsec shape, one record header
  // authenticated alongside each payload.
  std::vector<uint8_t> h_aad(g_aad_bytes ? g_aad_bytes : 1, 0);
  std::srand(50);
  for (uint32_t i = 0; i < g_aad_bytes; ++i) {
    h_aad[i] = (uint8_t)(std::rand() & 0xff);
  }
  for (size_t i = 0; i < h_nonce.size(); ++i) {
    h_nonce[i] = (uint8_t)std::rand();
  }
  for (size_t i = 0; i < h_pt.size(); ++i) {
    h_pt[i] = (uint8_t)std::rand();
  }

  std::vector<uint8_t> ref_ct(data_bytes);
  std::vector<uint8_t> ref_tag((size_t)POLY1305_TAG_BYTES * g_num_msgs);
  for (uint32_t m = 0; m < g_num_msgs; ++m) {
    ref::aead_encrypt(kAeadKey, &h_nonce[(size_t)CHACHA_NONCE_BYTES * m],
                      h_aad.data(), g_aad_bytes,
                      &h_pt[(size_t)msg_stride * m], msg_bytes,
                      &ref_ct[(size_t)msg_stride * m],
                      &ref_tag[(size_t)POLY1305_TAG_BYTES * m]);
  }

  vx_buffer_h key_buf, nonce_buf, aad_buf, src_buf, dst_buf, tag_buf;
  CHECK(vx_buffer_create(dev, CHACHA_KEY_BYTES, VX_MEM_READ, &key_buf));
  CHECK(vx_buffer_create(dev, h_nonce.size(), VX_MEM_READ, &nonce_buf));
  CHECK(vx_buffer_create(dev, h_aad.size(), VX_MEM_READ, &aad_buf));
  CHECK(vx_buffer_create(dev, data_bytes, VX_MEM_READ, &src_buf));
  CHECK(vx_buffer_create(dev, data_bytes, VX_MEM_WRITE, &dst_buf));
  CHECK(vx_buffer_create(dev, ref_tag.size(), VX_MEM_WRITE, &tag_buf));

  kernel_arg_t kernel_arg;
  kernel_arg.num_msgs = g_num_msgs;
  kernel_arg.blocks_per_msg = g_blocks_per_msg;
  kernel_arg.tail_bytes = g_tail_bytes;
  kernel_arg.aad_bytes = g_aad_bytes;
  CHECK(vx_buffer_address(aad_buf, &kernel_arg.aad_addr));
  CHECK(vx_buffer_address(key_buf, &kernel_arg.key_addr));
  CHECK(vx_buffer_address(nonce_buf, &kernel_arg.nonce_addr));
  CHECK(vx_buffer_address(src_buf, &kernel_arg.src_addr));
  CHECK(vx_buffer_address(dst_buf, &kernel_arg.dst_addr));
  CHECK(vx_buffer_address(tag_buf, &kernel_arg.tag_addr));

  vx_module_h mod;
  vx_kernel_h kern;
  CHECK(vx_module_load_file(dev, g_kernel_file, &mod));
  vx_result_t kr = vx_module_get_kernel(mod, kImpls[g_impl].kernel, &kern);
  if (kImpls[g_impl].needs_quad && (g_num_msgs % 4) != 0) {
    std::printf("impl '%s' has four lanes per message, so the message count "
                "must be a multiple of 4, got %u\n",
                kImpls[g_impl].label, g_num_msgs);
    return 1;
  }
  if (kr != VX_SUCCESS && kImpls[g_impl].needs_s2) {
    std::printf("SKIPPED: impl '%s' needs the stateful ChaCha engine; rebuild "
                "with CONFIGS=\"-DVX_CFG_EXT_SYM_CHACHA_S2_ENABLE\".\n",
                kImpls[g_impl].label);
    return 1;
  }
  if (kr != VX_SUCCESS && kImpls[g_impl].needs_sg4) {
    std::printf("SKIPPED: impl '%s' needs the fused subgroup forms; rebuild "
                "with CONFIGS=\"-DVX_CFG_EXT_SYM_CHACHA_SG4_ENABLE "
                "-DVX_CFG_EXT_AUTH_POLY_SG4_ENABLE\".\n",
                kImpls[g_impl].label);
    return 1;
  }
  if (kr != VX_SUCCESS && kImpls[g_impl].needs_mac) {
    std::printf("SKIPPED: impl '%s' needs the Poly1305 MAC; rebuild with "
                "CONFIGS=\"-DVX_CFG_EXT_AUTH_POLY_ENABLE\".\n",
                kImpls[g_impl].label);
    return 1;
  }
  if (kr != VX_SUCCESS && kImpls[g_impl].needs_xr) {
    std::printf("SKIPPED: impl '%s' needs the fused xor-rotate; rebuild "
                "with CONFIGS=\"-DVX_CFG_EXT_SYM_CHACHA_ENABLE\".\n",
                kImpls[g_impl].label);
    return 1;
  }
  CHECK(kr);

  vx_queue_info_t qi = { sizeof(qi), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
  vx_queue_h queue = nullptr;
  CHECK(vx_queue_create(dev, &qi, &queue));

  CHECK(vx_enqueue_write(queue, key_buf, 0, kAeadKey, CHACHA_KEY_BYTES, 0,
                         nullptr, nullptr));
  CHECK(vx_enqueue_write(queue, nonce_buf, 0, h_nonce.data(), h_nonce.size(), 0,
                         nullptr, nullptr));
  CHECK(vx_enqueue_write(queue, aad_buf, 0, h_aad.data(), h_aad.size(), 0,
                         nullptr, nullptr));
  CHECK(vx_enqueue_write(queue, src_buf, 0, h_pt.data(), h_pt.size(), 0,
                         nullptr, nullptr));

  // One persistent CTA per core with a grid-stride loop, the same geometry as
  // aes_gcm. Nothing is staged in local memory here, so the CTA is persistent
  // for comparability rather than to amortise a fill.
  vx_launch_info_t li;
  std::memset(&li, 0, sizeof(li));
  li.struct_size = sizeof(li);
  li.kernel = kern;
  li.args_host = &kernel_arg;
  li.args_size = sizeof(kernel_arg);
  li.ndim = 1;
  li.grid_dim[0] = (uint32_t)num_cores;
  li.grid_dim[1] = 1;
  li.grid_dim[2] = 1;
  li.block_dim[0] = (uint32_t)(num_warps * num_threads);
  li.block_dim[1] = 1;
  li.block_dim[2] = 1;
  li.lmem_size = 0;

  vx_event_h launch_ev = nullptr;
  vx_event_h ct_ev = nullptr;
  vx_event_h tag_ev = nullptr;
  std::vector<uint8_t> dev_ct(data_bytes);
  std::vector<uint8_t> dev_tag(ref_tag.size());
  CHECK(vx_enqueue_launch(queue, &li, 0, nullptr, &launch_ev));
  CHECK(vx_enqueue_read(queue, dev_ct.data(), dst_buf, 0, data_bytes, 1,
                        &launch_ev, &ct_ev));
  CHECK(vx_enqueue_read(queue, dev_tag.data(), tag_buf, 0, dev_tag.size(), 1,
                        &launch_ev, &tag_ev));
  CHECK(vx_event_wait_value(ct_ev, 1, VX_TIMEOUT_INFINITE));
  CHECK(vx_event_wait_value(tag_ev, 1, VX_TIMEOUT_INFINITE));

  // MCYCLE is per-core elapsed time, so reduce it with max; MINSTRET counts
  // retired instructions, so sum it. Passing the broadcast core id would sum
  // both, which is silently wrong for cycles.
  uint64_t cycles = 0;
  uint64_t instrs = 0;
  for (uint64_t core = 0; core < num_cores; ++core) {
    uint64_t v = 0;
    CHECK(vx_device_mpm_query(dev, VX_DCR_MPM_CLASS_BASE, VX_CSR_MCYCLE,
                              (uint32_t)core, &v));
    if (v > cycles) {
      cycles = v;
    }
    CHECK(vx_device_mpm_query(dev, VX_DCR_MPM_CLASS_BASE, VX_CSR_MINSTRET,
                              (uint32_t)core, &v));
    instrs += v;
  }

  int errors = 0;
  for (uint32_t m = 0; m < g_num_msgs && errors < 8; ++m) {
    // Index by stride, compare msg_bytes: the padding in each slot is not
    // ciphertext and is not authenticated, so comparing it would be comparing
    // uninitialised memory.
    errors += compare("ciphertext", m, &dev_ct[(size_t)msg_stride * m],
                      &ref_ct[(size_t)msg_stride * m], msg_bytes);
    errors += compare("tag", m, &dev_tag[(size_t)POLY1305_TAG_BYTES * m],
                      &ref_tag[(size_t)POLY1305_TAG_BYTES * m],
                      POLY1305_TAG_BYTES);
  }

  // bytes_per_cycle is the field to compare against aes_gcm: the two
  // applications have different block sizes but the same byte.
  const uint64_t total_blocks = (uint64_t)g_num_msgs * g_blocks_per_msg;
  std::printf("CHACHA_POLY_PERF: impl=%s key_bits=256 mode=aead msgs=%u "
              "blocks_per_msg=%u blocks=%llu bytes=%zu cycles=%llu "
              "instrs=%llu cycles_per_block=%.2f instrs_per_block=%.2f "
              "bytes_per_cycle=%.4f cores=%lu warps=%lu threads=%lu\n",
              kImpls[g_impl].label, g_num_msgs, g_blocks_per_msg,
              (unsigned long long)total_blocks, data_bytes,
              (unsigned long long)cycles, (unsigned long long)instrs,
              (double)cycles / (double)total_blocks,
              (double)instrs / (double)total_blocks,
              (double)data_bytes / (double)cycles,
              (unsigned long)num_cores, (unsigned long)num_warps,
              (unsigned long)num_threads);

  vx_device_dump_perf(dev, stdout);

  vx_event_release(tag_ev);
  vx_event_release(ct_ev);
  vx_event_release(launch_ev);
  vx_queue_release(queue);
  vx_kernel_release(kern);
  vx_module_release(mod);
  vx_buffer_release(tag_buf);
  vx_buffer_release(dst_buf);
  vx_buffer_release(src_buf);
  vx_buffer_release(aad_buf);
  vx_buffer_release(nonce_buf);
  vx_buffer_release(key_buf);
  vx_device_release(dev);

  if (errors != 0) {
    std::printf("FAILED!\n");
    return 1;
  }
  std::printf("PASSED!\n");
  return 0;
}
