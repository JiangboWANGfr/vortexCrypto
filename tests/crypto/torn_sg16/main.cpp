// Host for the torn-sg16 probe. See kernel.cpp for what it does and why.
//
// The expected outcome is a REJECTION, not a number. Run it through
// ci/crypto_torn_sg16.sh, which asserts that both models stop.
#include <vortex2.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "common.h"

#define CHECK(x)                                                              \
  do {                                                                        \
    int _e = (x);                                                             \
    if (_e != 0) { std::printf("FATAL: %s = %d\n", #x, _e); std::exit(1); }    \
  } while (0)

int main(int argc, char** argv) {
  (void)argc; (void)argv;

  vx_device_h dev = nullptr;
  CHECK(vx_device_open(0, &dev));

  uint64_t num_threads = 0, num_cores = 0, isa_flags = 0;
  CHECK(vx_device_query(dev, VX_CAPS_NUM_THREADS, &num_threads));
  CHECK(vx_device_query(dev, VX_CAPS_NUM_CORES, &num_cores));
  CHECK(vx_device_query(dev, VX_CAPS_ISA_FLAGS, &isa_flags));
  if ((isa_flags & VX_ISA_EXT_SYM) == 0) {
    std::printf("SKIPPED: needs EX_SYM\n");
    vx_device_release(dev);
    return 0;
  }
  if (num_threads < 16) {
    std::printf("SKIPPED: needs at least 16 threads per warp, has %lu\n",
                (unsigned long)num_threads);
    vx_device_release(dev);
    return 0;
  }

  const uint32_t lanes = (uint32_t)num_threads;
  const uint64_t bytes = (uint64_t)lanes * 4;

  vx_buffer_h src_b = nullptr, dst_b = nullptr;
  CHECK(vx_buffer_create(dev, bytes, VX_MEM_READ_WRITE, &src_b));
  CHECK(vx_buffer_create(dev, bytes, VX_MEM_READ_WRITE, &dst_b));
  uint64_t src_addr = 0, dst_addr = 0;
  CHECK(vx_buffer_address(src_b, &src_addr));
  CHECK(vx_buffer_address(dst_b, &dst_addr));

  vx_module_h mod = nullptr;
  vx_kernel_h kern = nullptr;
  CHECK(vx_module_load_file(dev, "kernel.vxbin", &mod));
  if (vx_module_get_kernel(mod, "torn_sg16", &kern) != 0) {
    std::printf("SKIPPED: kernel not built (needs SYM_CHACHA_SG16)\n");
    vx_device_release(dev);
    return 0;
  }

  kernel_arg_t ka;
  std::memset(&ka, 0, sizeof(ka));
  ka.src = src_addr;
  ka.dst = dst_addr;
  ka.lanes = lanes;

  vx_launch_info_t li;
  std::memset(&li, 0, sizeof(li));
  li.struct_size = sizeof(li);
  li.kernel = kern;
  li.args_host = &ka;
  li.args_size = sizeof(ka);
  li.ndim = 1;
  // grid_dim must be >= NUM_CORES. A smaller grid is accepted and then
  // dispatches nothing, with no error, and the output buffer comes back
  // untouched -- which is how the first run of the quad probe reported that
  // the guard had not fired when the kernel had simply never run.
  li.grid_dim[0] = (uint32_t)num_cores;
  li.grid_dim[1] = 1;  li.grid_dim[2] = 1;
  li.block_dim[0] = lanes; li.block_dim[1] = 1; li.block_dim[2] = 1;

  vx_queue_info_t qi = { sizeof(qi), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
  vx_queue_h queue = nullptr;
  CHECK(vx_queue_create(dev, &qi, &queue));

  std::printf("issuing chacha.dr.sg16 on subgroups masked 0x7fff (%u lanes)\n",
              lanes);
  std::fflush(stdout);

  std::vector<uint32_t> out(lanes, 0xDEADBEEFu);
  vx_event_h lev = nullptr, rev = nullptr;
  CHECK(vx_enqueue_launch(queue, &li, 0, nullptr, &lev));
  CHECK(vx_enqueue_read(queue, out.data(), dst_b, 0, bytes, 1, &lev, &rev));
  CHECK(vx_event_wait_value(rev, 1, VX_TIMEOUT_INFINITE));

  // Reaching here means neither model stopped, which is the failure this probe
  // exists to detect. Print what came back so the reader can see whether a
  // stale lane was picked up.
  std::printf("NOT REJECTED -- the torn-sg16 guard did not fire\n");
  for (uint32_t i = 0; i < lanes; ++i)
    std::printf("  lane %2u: 0x%08x%s\n", i, out[i],
                (i & 15u) == 15u ? "  (inactive)" : "");

  CHECK(vx_queue_release(queue));
  CHECK(vx_buffer_release(src_b));
  CHECK(vx_buffer_release(dst_b));
  CHECK(vx_device_release(dev));
  return 2;
}
