#include <vortex2.h>
#include <VX_types.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <unistd.h>
#include "common.h"
#include "aes_gcm_ref.h"

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

namespace {

const char* g_kernel_file = "kernel.vxbin";
uint32_t g_num_msgs = 256;
uint32_t g_blocks_per_msg = 16;
uint32_t g_impl = 0;

// Every implementation is a separate entry point in the same binary, sharing
// this host program's buffers, vectors and counter reduction. Only the device
// code differs, so a comparison between two rows measures the implementation
// and nothing else. Hardware-instruction variants join this table behind the
// extension guard that defines them.
struct impl_t {
  const char* kernel;
  const char* label;
};

const impl_t kImpls[] = {
  { "aes_gcm_sw_ttable", "sw_ttable" },
  // Same host program, buffers, vectors, counter reduction and output format;
  // only the device code differs, which is the whole point of selecting by -i
  // rather than building a second application.
  { "aes_gcm_hw_s1",     "hw_s1" },
};

const uint32_t kNumImpls = (uint32_t)(sizeof(kImpls) / sizeof(kImpls[0]));

// AES-128-GCM with a 96-bit IV and empty AAD, from McGrew & Viega's GCM
// specification (also NIST CAVP gcmEncryptExtIV128). Two cases: one block,
// which exercises a single GHASH multiply, and four blocks, which exercises
// the chain and the length block.
struct gcm_vector_t {
  const char* name;
  const uint8_t key[16];
  const uint8_t iv[GCM_IV_BYTES];
  uint32_t blocks;
  const uint8_t pt[64];
  const uint8_t ct[64];
  const uint8_t tag[GCM_TAG_BYTES];
};

const gcm_vector_t kGcmVectors[] = {
  { "GCM test case 2",
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    1,
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
      0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78 },
    { 0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
      0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf } },
  { "GCM test case 3",
    { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
      0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08 },
    { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
      0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 },
    4,
    { 0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
      0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
      0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
      0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
      0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
      0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
      0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
      0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55 },
    { 0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
      0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
      0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
      0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
      0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
      0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
      0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
      0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85 },
    { 0x4d, 0x5c, 0x2a, 0xf3, 0x27, 0xcd, 0x64, 0xa6,
      0x2c, 0xf3, 0x5a, 0xbd, 0x2b, 0xa6, 0xfa, 0xb4 } },
};

// FIPS-197 Appendix C.1: the raw AES-128 block cipher, so a broken S-box or
// MixColumns is caught before GCM ever runs.
const uint8_t kKatAesKey[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
const uint8_t kKatAesPt[16] = {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};
const uint8_t kKatAesCt[16] = {
  0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
  0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
};

void show_usage() {
  std::printf(
      "AES-128-GCM\n"
      "Usage: [-n msgs] [-b blocks_per_msg] [-i impl] [-k kernel] [-h]\n");
  for (uint32_t i = 0; i < kNumImpls; ++i) {
    std::printf("  -i%u  %s\n", i, kImpls[i].label);
  }
}

void parse_args(int argc, char** argv) {
  int c;
  while ((c = getopt(argc, argv, "n:b:i:k:h")) != -1) {
    switch (c) {
    case 'n': g_num_msgs = (uint32_t)std::atoi(optarg); break;
    case 'b': g_blocks_per_msg = (uint32_t)std::atoi(optarg); break;
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
  uint8_t rk[AES128_RK_BYTES];
  aes_gcm_ref::key_expand(kKatAesKey, rk);
  uint8_t block[16];
  aes_gcm_ref::encrypt_block(rk, kKatAesPt, block);
  if (std::memcmp(block, kKatAesCt, 16) != 0) {
    std::printf("reference AES-128 does not match FIPS-197 C.1\n");
    return 1;
  }

  for (const gcm_vector_t& v : kGcmVectors) {
    aes_gcm_ref::key_expand(v.key, rk);
    uint8_t zero[16] = {0};
    uint8_t h[16];
    aes_gcm_ref::encrypt_block(rk, zero, h);
    uint8_t ct[64];
    uint8_t tag[GCM_TAG_BYTES];
    aes_gcm_ref::gcm_encrypt(rk, h, v.iv, v.pt, v.blocks, ct, tag);
    if (std::memcmp(ct, v.ct, AES_BLOCK_BYTES * v.blocks) != 0) {
      std::printf("reference ciphertext does not match %s\n", v.name);
      return 1;
    }
    if (std::memcmp(tag, v.tag, GCM_TAG_BYTES) != 0) {
      std::printf("reference tag does not match %s\n", v.name);
      return 1;
    }
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
  std::printf("reference matches FIPS-197 C.1 and the NIST GCM vector\n");

  vx_device_h dev = nullptr;
  CHECK(vx_device_open(0, &dev));

  uint64_t num_cores = 0;
  uint64_t num_warps = 0;
  uint64_t num_threads = 0;
  CHECK(vx_device_query(dev, VX_CAPS_NUM_CORES, &num_cores));
  CHECK(vx_device_query(dev, VX_CAPS_NUM_WARPS, &num_warps));
  CHECK(vx_device_query(dev, VX_CAPS_NUM_THREADS, &num_threads));

  const uint32_t msg_bytes = AES_BLOCK_BYTES * g_blocks_per_msg;
  const size_t data_bytes = (size_t)msg_bytes * g_num_msgs;

  std::printf("messages=%u blocks/msg=%u bytes=%zu cores=%lu warps=%lu "
              "threads=%lu\n",
              g_num_msgs, g_blocks_per_msg, data_bytes,
              (unsigned long)num_cores, (unsigned long)num_warps,
              (unsigned long)num_threads);

  // Host-side setup: one key for every message, one IV each.
  const uint8_t* key = kGcmVectors[1].key;
  uint8_t rk[AES128_RK_BYTES];
  aes_gcm_ref::key_expand(key, rk);
  uint8_t zero[16] = {0};
  uint8_t h[16];
  aes_gcm_ref::encrypt_block(rk, zero, h);

  std::vector<uint32_t> rk_words(AES128_RK_BYTES / 4);
  aes_gcm_ref::rk_to_words(rk, rk_words.data());
  std::vector<uint32_t> te(AES_TE_TABLES * AES_TE_ENTRIES);
  aes_gcm_ref::build_te(te.data());
  std::vector<uint8_t> htable(GHASH_TABLE_BYTES);
  aes_gcm_ref::ghash_table(h, htable.data());

  std::vector<uint8_t> h_iv((size_t)GCM_IV_BYTES * g_num_msgs);
  std::vector<uint8_t> h_pt(data_bytes);
  std::srand(50);
  for (size_t i = 0; i < h_iv.size(); ++i) {
    h_iv[i] = (uint8_t)std::rand();
  }
  for (size_t i = 0; i < h_pt.size(); ++i) {
    h_pt[i] = (uint8_t)std::rand();
  }

  std::vector<uint8_t> ref_ct(data_bytes);
  std::vector<uint8_t> ref_tag((size_t)GCM_TAG_BYTES * g_num_msgs);
  for (uint32_t m = 0; m < g_num_msgs; ++m) {
    aes_gcm_ref::gcm_encrypt(rk, h, &h_iv[(size_t)GCM_IV_BYTES * m],
                             &h_pt[(size_t)msg_bytes * m], g_blocks_per_msg,
                             &ref_ct[(size_t)msg_bytes * m],
                             &ref_tag[(size_t)GCM_TAG_BYTES * m]);
  }

  vx_buffer_h rk_buf, te_buf, ht_buf, h_buf, iv_buf, src_buf, dst_buf, tag_buf;
  CHECK(vx_buffer_create(dev, rk_words.size() * 4, VX_MEM_READ, &rk_buf));
  CHECK(vx_buffer_create(dev, te.size() * 4, VX_MEM_READ, &te_buf));
  CHECK(vx_buffer_create(dev, htable.size(), VX_MEM_READ, &ht_buf));
  CHECK(vx_buffer_create(dev, 16, VX_MEM_READ, &h_buf));
  CHECK(vx_buffer_create(dev, h_iv.size(), VX_MEM_READ, &iv_buf));
  CHECK(vx_buffer_create(dev, data_bytes, VX_MEM_READ, &src_buf));
  CHECK(vx_buffer_create(dev, data_bytes, VX_MEM_WRITE, &dst_buf));
  CHECK(vx_buffer_create(dev, ref_tag.size(), VX_MEM_WRITE, &tag_buf));

  kernel_arg_t kernel_arg;
  kernel_arg.num_msgs = g_num_msgs;
  kernel_arg.blocks_per_msg = g_blocks_per_msg;
  CHECK(vx_buffer_address(rk_buf, &kernel_arg.rk_addr));
  CHECK(vx_buffer_address(te_buf, &kernel_arg.te_addr));
  CHECK(vx_buffer_address(ht_buf, &kernel_arg.htable_addr));
  CHECK(vx_buffer_address(h_buf, &kernel_arg.h_addr));
  CHECK(vx_buffer_address(iv_buf, &kernel_arg.iv_addr));
  CHECK(vx_buffer_address(src_buf, &kernel_arg.src_addr));
  CHECK(vx_buffer_address(dst_buf, &kernel_arg.dst_addr));
  CHECK(vx_buffer_address(tag_buf, &kernel_arg.tag_addr));

  vx_module_h mod;
  vx_kernel_h kern;
  CHECK(vx_module_load_file(dev, g_kernel_file, &mod));
  CHECK(vx_module_get_kernel(mod, kImpls[g_impl].kernel, &kern));

  vx_queue_info_t qi = { sizeof(qi), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
  vx_queue_h queue = nullptr;
  CHECK(vx_queue_create(dev, &qi, &queue));

  CHECK(vx_enqueue_write(queue, rk_buf, 0, rk_words.data(),
                         rk_words.size() * 4, 0, nullptr, nullptr));
  CHECK(vx_enqueue_write(queue, te_buf, 0, te.data(), te.size() * 4, 0,
                         nullptr, nullptr));
  CHECK(vx_enqueue_write(queue, ht_buf, 0, htable.data(), htable.size(), 0,
                         nullptr, nullptr));
  CHECK(vx_enqueue_write(queue, h_buf, 0, h, 16, 0, nullptr, nullptr));
  CHECK(vx_enqueue_write(queue, iv_buf, 0, h_iv.data(), h_iv.size(), 0,
                         nullptr, nullptr));
  CHECK(vx_enqueue_write(queue, src_buf, 0, h_pt.data(), h_pt.size(), 0,
                         nullptr, nullptr));

  // One persistent CTA per core so the local-memory tables are filled once
  // and then amortised over a grid-stride loop.
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
  li.lmem_size = AES_GCM_LMEM_BYTES;

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
    errors += compare("ciphertext", m, &dev_ct[(size_t)msg_bytes * m],
                      &ref_ct[(size_t)msg_bytes * m], msg_bytes);
    errors += compare("tag", m, &dev_tag[(size_t)GCM_TAG_BYTES * m],
                      &ref_tag[(size_t)GCM_TAG_BYTES * m], GCM_TAG_BYTES);
  }

  const uint64_t total_blocks = (uint64_t)g_num_msgs * g_blocks_per_msg;
  std::printf("AES_GCM_PERF: impl=%s key_bits=128 mode=gcm msgs=%u "
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
  vx_buffer_release(iv_buf);
  vx_buffer_release(ht_buf);
  vx_buffer_release(te_buf);
  vx_buffer_release(rk_buf);
  vx_device_release(dev);

  if (errors != 0) {
    std::printf("FAILED!\n");
    return 1;
  }
  std::printf("PASSED!\n");
  return 0;
}
