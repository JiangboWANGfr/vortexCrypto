#include <vortex2.h>
#include <VX_types.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <vector>
#include "common.h"

#define CHECK(_expr)                                              \
  do {                                                            \
    int _ret = (_expr);                                           \
    if (_ret != 0) {                                              \
      std::printf("FAILED: %s = %d\n", #_expr, _ret);             \
      std::exit(1);                                               \
    }                                                             \
  } while (false)

// --- host reference --------------------------------------------------------
// Written from the ratified specification, independently of both the RTL and
// the simx model, so that agreement between the three is evidence rather than
// a shared assumption.

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
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static uint32_t ref_rol32(uint32_t x, uint32_t n) {
  n &= 31;
  return n ? ((x << n) | (x >> (32 - n))) : x;
}

static uint8_t ref_xtime(uint8_t x) {
  return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static uint32_t ref_clmul(uint32_t a, uint32_t b, bool high) {
  uint64_t p = 0;
  for (int k = 0; k < 32; ++k) {
    if ((b >> k) & 1) {
      p ^= ((uint64_t)a << k);
    }
  }
  return high ? (uint32_t)(p >> 32) : (uint32_t)p;
}

static uint32_t ref_brev8(uint32_t a) {
  uint32_t r = 0;
  for (int j = 0; j < 4; ++j) {
    uint8_t byte = (uint8_t)((a >> (8 * j)) & 0xff);
    uint8_t rev = 0;
    for (int k = 0; k < 8; ++k) {
      if ((byte >> k) & 1) {
        rev |= (uint8_t)(1u << (7 - k));
      }
    }
    r |= ((uint32_t)rev << (8 * j));
  }
  return r;
}

static uint32_t ref_aes32(uint32_t a, uint32_t b, uint32_t bs, bool mix) {
  uint8_t s = kSbox[(b >> (8 * bs)) & 0xff];
  uint32_t so;
  if (mix) {
    uint8_t s2 = ref_xtime(s);
    uint8_t s3 = (uint8_t)(s2 ^ s);
    so = ((uint32_t)s3 << 24) | ((uint32_t)s << 16) | ((uint32_t)s << 8) | s2;
  } else {
    so = s;
  }
  return a ^ ref_rol32(so, 8 * bs);
}

// Reference for the fused reduction, written from its definition rather than
// from either model: carry-less multiply by the GF(2^128) reduction constant
// 0x87, then accumulate into rs1.
static uint32_t ref_ghred(uint32_t acc, uint32_t x, bool high) {
  uint64_t p = 0;
  for (int k = 0; k < 32; ++k) {
    if ((0x87u >> k) & 1) {
      p ^= ((uint64_t)x << k);
    }
  }
  return acc ^ (high ? (uint32_t)(p >> 32) : (uint32_t)p);
}

static const char* kOpNames[ISA_NUM_OPS] = {
  "clmul", "clmulh", "brev8", "aes32esi", "aes32esmi", "rori", "ghred32l", "ghred32h"
};

// The four shamt values the kernel uses, indexed by vector.
static const uint32_t kRoriShamt[4] = { 16, 20, 24, 25 };

static uint32_t ref_op(uint32_t op, uint32_t v, uint32_t a, uint32_t b) {
  switch (op) {
  case ISA_OP_CLMUL:     return ref_clmul(a, b, false);
  case ISA_OP_CLMULH:    return ref_clmul(a, b, true);
  case ISA_OP_BREV8:     return ref_brev8(a);
  case ISA_OP_AES32ESI:  return ref_aes32(a, b, v & 3, false);
  case ISA_OP_AES32ESMI: return ref_aes32(a, b, v & 3, true);
  case ISA_OP_GHRED32L:  return ref_ghred(a, b, false);
  case ISA_OP_GHRED32H:  return ref_ghred(a, b, true);
  case ISA_OP_RORI:      return ref_rol32(a, (32 - kRoriShamt[v & 3]) & 31);
  default:               return 0;
  }
}

const char* g_kernel_file = "kernel.vxbin";

int main(int argc, char* argv[]) {
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
      g_kernel_file = argv[++i];
    }
  }

  // Operand vectors. Chosen to cover the cases that distinguish a correct
  // implementation from the instructions these encodings alias to when
  // mis-decoded: zero, identity, single bits at both ends, all-ones (which
  // makes clmul differ maximally from mul), and values whose top bit exercises
  // the 0x11b reduction inside MixColumns.
  const uint32_t src_a[ISA_NUM_VECTORS] = {
    0x00000000u, 0x00000001u, 0xffffffffu, 0x80000000u,
    0x01020304u, 0xdeadbeefu, 0x00000003u, 0xa5a5a5a5u,
    0x12345678u, 0x0000ffffu, 0xffff0000u, 0x7f7f7f7fu,
    0x80808080u, 0x0f0f0f0fu, 0xcafebabeu, 0x5a5a5a5au
  };
  const uint32_t src_b[ISA_NUM_VECTORS] = {
    0xffffffffu, 0x00000001u, 0xffffffffu, 0x00000002u,
    0x63636363u, 0x00000010u, 0x00000003u, 0x5a5a5a5au,
    0x9abcdef0u, 0xffff0000u, 0x0000ffffu, 0x80808080u,
    0x7f7f7f7fu, 0xf0f0f0f0u, 0xbabecafeu, 0xa5a5a5a5u
  };

  vx_device_h dev;
  CHECK(vx_device_open(0, &dev));

  uint64_t num_cores = 1, num_warps = 1, num_threads = 1;
  CHECK(vx_device_query(dev, VX_CAPS_NUM_CORES, &num_cores));
  CHECK(vx_device_query(dev, VX_CAPS_NUM_WARPS, &num_warps));
  CHECK(vx_device_query(dev, VX_CAPS_NUM_THREADS, &num_threads));

  vx_buffer_h a_buf, b_buf, d_buf;
  CHECK(vx_buffer_create(dev, sizeof(src_a), VX_MEM_READ, &a_buf));
  CHECK(vx_buffer_create(dev, sizeof(src_b), VX_MEM_READ, &b_buf));
  CHECK(vx_buffer_create(dev, ISA_NUM_RESULTS * sizeof(uint32_t), VX_MEM_WRITE, &d_buf));

  kernel_arg_t kernel_arg;
  std::memset(&kernel_arg, 0, sizeof(kernel_arg));
  CHECK(vx_buffer_address(a_buf, &kernel_arg.src_a));
  CHECK(vx_buffer_address(b_buf, &kernel_arg.src_b));
  CHECK(vx_buffer_address(d_buf, &kernel_arg.dst));

  vx_module_h mod;
  vx_kernel_h kern;
  CHECK(vx_module_load_file(dev, g_kernel_file, &mod));
  CHECK(vx_module_get_kernel(mod, "isa_check", &kern));

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

  vx_queue_info_t qi = { sizeof(qi), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
  vx_queue_h queue;
  CHECK(vx_queue_create(dev, &qi, &queue));

  CHECK(vx_enqueue_write(queue, a_buf, 0, src_a, sizeof(src_a), 0, nullptr, nullptr));
  CHECK(vx_enqueue_write(queue, b_buf, 0, src_b, sizeof(src_b), 0, nullptr, nullptr));

  vx_event_h launch_ev = nullptr;
  vx_event_h read_ev = nullptr;
  std::vector<uint32_t> got(ISA_NUM_RESULTS);
  CHECK(vx_enqueue_launch(queue, &li, 0, nullptr, &launch_ev));
  CHECK(vx_enqueue_read(queue, got.data(), d_buf, 0,
                        got.size() * sizeof(uint32_t), 1, &launch_ev, &read_ev));
  CHECK(vx_event_wait_value(read_ev, 1, VX_TIMEOUT_INFINITE));

  int failures = 0;
  for (uint32_t op = 0; op < ISA_NUM_OPS; ++op) {
    int op_failures = 0;
    for (uint32_t v = 0; v < ISA_NUM_VECTORS; ++v) {
      uint32_t want = ref_op(op, v, src_a[v], src_b[v]);
      uint32_t have = got[op * ISA_NUM_VECTORS + v];
      if (want != have) {
        if (op_failures < 4) {
          std::printf("  %-9s v%-2u a=%08x b=%08x  got %08x want %08x\n",
                      kOpNames[op], v, src_a[v], src_b[v], have, want);
        }
        ++op_failures;
      }
    }
    std::printf("%-9s : %s (%u/%u)\n", kOpNames[op],
                op_failures ? "FAIL" : "ok",
                ISA_NUM_VECTORS - op_failures, ISA_NUM_VECTORS);
    failures += op_failures;
  }

  vx_kernel_release(kern);
  vx_module_release(mod);
  vx_queue_release(queue);
  vx_buffer_release(a_buf);
  vx_buffer_release(b_buf);
  vx_buffer_release(d_buf);
  vx_device_release(dev);

  if (failures != 0) {
    std::printf("FAILED! %d mismatches\n", failures);
    return 1;
  }
  std::printf("PASSED!\n");
  return 0;
}
