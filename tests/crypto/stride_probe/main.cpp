#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <vortex2.h>
#include "common.h"

#define CHECK(_e)                                                             \
  do {                                                                        \
    int _r = (_e);                                                            \
    if (_r != 0) {                                                            \
      std::printf("FATAL: '%s' returned %d (%s:%d)\n", #_e, _r,               \
                  __FILE__, __LINE__);                                        \
      std::exit(1);                                                           \
    }                                                                         \
  } while (0)

#define FATAL(...)                                                            \
  do { std::printf("FATAL: " __VA_ARGS__); std::exit(1); } while (0)

// --------------------------------------------------------------------------
// Geometry, taken from the resolved config the host was compiled against.
// tests/regression/common.mk puts the gen_config.py --cflags projection into
// CXXFLAGS, so these are the same numbers the RTL was built from.
// --------------------------------------------------------------------------
#ifndef VX_CFG_DCACHE_SIZE
#error "VX_CFG_DCACHE_SIZE not projected into CXXFLAGS -- check common.mk"
#endif
static const uint32_t kWaySpan  = VX_CFG_DCACHE_SIZE / VX_CFG_DCACHE_NUM_WAYS;
static const uint32_t kLine     = VX_CFG_DCACHE_LINE_SIZE;
static const uint32_t kNumSlots = kWaySpan / kLine;   // distinct (bank,set) pairs

static const uint64_t kRegionBytes = 2u << 20;        // 2 MiB per region
static const char*    kKernelFile  = "kernel.vxbin";

// (bank,set) slot of a device address: {set,bank,offset} occupy the low
// log2(DCACHE_SIZE/NUM_WAYS) bits (hw/rtl/cache/VX_cache_define.vh:23-71), so
// the slot is simply (addr / LINE) % (WAY_SPAN / LINE).
static inline uint32_t slot_of(uint64_t addr) {
  return (uint32_t)((addr / kLine) % kNumSlots);
}

struct Point {
  uint32_t alias_stride;
  uint32_t ctrl_stride;
  uint32_t n_alias;
};

int main(int argc, char** argv) {
  uint32_t iters   = 1024;
  uint32_t warmup  = 64;
  uint32_t repeats = 3;
  uint32_t opt_alias_stride = 8192;   // vx_start.S's per-hart stack stride
  uint32_t opt_ctrl_stride  = 8320;   // 8192 + 2 lines: rotates the slot by 2
  int      opt_n_alias      = -1;     // -1 => all lanes
  std::string sweep = "stride";
  uint32_t opt_grid = 0;      // CTAs; 0 => NUM_CORES (see note below)
  uint32_t opt_block = 0;     // threads/CTA; 0 => NUM_THREADS (one warp)

  int c;
  while ((c = ::getopt(argc, argv, "i:w:r:s:c:a:m:G:B:h")) != -1) {
    switch (c) {
    case 'i': iters   = (uint32_t)std::strtoul(optarg, nullptr, 0); break;
    case 'w': warmup  = (uint32_t)std::strtoul(optarg, nullptr, 0); break;
    case 'r': repeats = (uint32_t)std::strtoul(optarg, nullptr, 0); break;
    case 's': opt_alias_stride = (uint32_t)std::strtoul(optarg, nullptr, 0); break;
    case 'c': opt_ctrl_stride  = (uint32_t)std::strtoul(optarg, nullptr, 0); break;
    case 'a': opt_n_alias = (int)std::strtol(optarg, nullptr, 0); break;
    case 'm': sweep = optarg; break;
    case 'G': opt_grid  = (uint32_t)std::strtoul(optarg, nullptr, 0); break;
    case 'B': opt_block = (uint32_t)std::strtoul(optarg, nullptr, 0); break;
    default:
      std::printf("usage: %s [-m stride|ways|point] [-s alias_stride] "
                  "[-c ctrl_stride] [-a n_alias] [-i iters] [-w warmup] "
                  "[-r repeats]\n", argv[0]);
      return 0;
    }
  }

  vx_device_h dev = nullptr;
  CHECK(vx_device_open(0, &dev));

  uint64_t num_cores = 0, num_warps = 0, num_threads = 0;
  CHECK(vx_device_query(dev, VX_CAPS_NUM_CORES,   &num_cores));
  CHECK(vx_device_query(dev, VX_CAPS_NUM_WARPS,   &num_warps));
  CHECK(vx_device_query(dev, VX_CAPS_NUM_THREADS, &num_threads));

  // ---------------------------------------------------------------------
  // GATE 1 -- the shape actually took effect.
  //
  // These caps are decoded from a control-plane register read out of the
  // device (sw/runtime/common/caps.h:50, CP_REG_GPU_DEV_CAPS), i.e. from
  // librtlsim.so / libsimx.so as built. The VX_CFG_* below come from the
  // -D flags this host binary was compiled with. Section 15.2 of the
  // proposal records a measurement lost to exactly this mismatch: CONFIGS
  // passed to a test directory rebuilt only the kernel and left the shape
  // at whatever the .so was last built with, silently. It is no longer
  // silent.
  // ---------------------------------------------------------------------
  if (num_threads != VX_CFG_NUM_THREADS || num_warps != VX_CFG_NUM_WARPS ||
      num_cores != VX_CFG_NUM_CORES) {
    FATAL("shape mismatch: device reports c%lluw%llut%llu but this binary was "
          "built for c%dw%dt%d. The runtime library was not rebuilt for these "
          "CONFIGS. Re-run as:\n"
          "  make -C <root>/sw/runtime clean && CONFIGS=\"...\" make run-rtlsim\n",
          (unsigned long long)num_cores, (unsigned long long)num_warps,
          (unsigned long long)num_threads,
          VX_CFG_NUM_CORES, VX_CFG_NUM_WARPS, VX_CFG_NUM_THREADS);
  }
  if (num_threads > STRIDE_PROBE_LANES)
    FATAL("NUM_THREADS=%llu exceeds STRIDE_PROBE_LANES=%d\n",
          (unsigned long long)num_threads, STRIDE_PROBE_LANES);

  const uint32_t lanes = (uint32_t)num_threads;

  // ---------------------------------------------------------------------
  // Buffers.
  // ---------------------------------------------------------------------
  const uint64_t buf_bytes  = 2 * kRegionBytes + 2 * kWaySpan;
  const uint64_t sink_bytes = (uint64_t)STRIDE_PROBE_SLOTS * STRIDE_PROBE_LANES * 4;
  const uint64_t out_bytes  = (uint64_t)STRIDE_PROBE_SLOTS * sizeof(probe_result_t);

  vx_buffer_h buf_b = nullptr, out_b = nullptr, sink_b = nullptr;
  CHECK(vx_buffer_create(dev, buf_bytes,  VX_MEM_READ_WRITE, &buf_b));
  CHECK(vx_buffer_create(dev, out_bytes,  VX_MEM_READ_WRITE, &out_b));
  CHECK(vx_buffer_create(dev, sink_bytes, VX_MEM_READ_WRITE, &sink_b));

  uint64_t buf_addr = 0, out_addr = 0, sink_addr = 0;
  CHECK(vx_buffer_address(buf_b,  &buf_addr));
  CHECK(vx_buffer_address(out_b,  &out_addr));
  CHECK(vx_buffer_address(sink_b, &sink_addr));

  // Place region A on (bank,set) slot 0 and region B on slot 1, so that a
  // ctrl_stride that rotates the slot by 2 gives every control lane its own
  // odd slot and never collides with region A.
  auto align_to_slot = [&](uint64_t start_ofs, uint32_t want) -> uint64_t {
    uint64_t o = (start_ofs + kLine - 1) & ~(uint64_t)(kLine - 1);
    while (slot_of(buf_addr + o) != want) o += kLine;
    return o;
  };
  const uint64_t ofsA = align_to_slot(0, 0);
  const uint64_t ofsB = align_to_slot(ofsA + kRegionBytes, 1);
  if (ofsB + kRegionBytes > buf_bytes) FATAL("region layout overflow\n");

  // buf[i] = i makes EVERY word a self-referencing one-node chain, so a single
  // upload serves every stride in the sweep and there is nothing per-point that
  // could go stale.
  {
    std::vector<uint32_t> img(buf_bytes / 4);
    for (size_t i = 0; i < img.size(); ++i) img[i] = (uint32_t)i;
    vx_queue_info_t qi0 = { sizeof(qi0), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
    vx_queue_h q0 = nullptr;
    CHECK(vx_queue_create(dev, &qi0, &q0));
    vx_event_h ev = nullptr;
    CHECK(vx_enqueue_write(q0, buf_b, 0, img.data(), buf_bytes, 0, nullptr, &ev));
    CHECK(vx_event_wait_value(ev, 1, VX_TIMEOUT_INFINITE));
    CHECK(vx_queue_release(q0));
  }

  vx_module_h mod = nullptr;
  vx_kernel_h kern = nullptr;
  CHECK(vx_module_load_file(dev, kKernelFile, &mod));
  CHECK(vx_module_get_kernel(mod, "stride_probe", &kern));

  vx_queue_info_t qi = { sizeof(qi), nullptr, VX_QUEUE_PRIORITY_NORMAL, 0 };
  vx_queue_h queue = nullptr;
  CHECK(vx_queue_create(dev, &qi, &queue));

  std::printf("# stride_probe  shape=c%lluw%llut%llu  dcache=%dB/%dway/%dB-line"
              "  way_span=%uB  slots=%u  iters=%u warmup=%u repeats=%u\n",
              (unsigned long long)num_cores, (unsigned long long)num_warps,
              (unsigned long long)num_threads,
              VX_CFG_DCACHE_SIZE, VX_CFG_DCACHE_NUM_WAYS,
              VX_CFG_DCACHE_LINE_SIZE, kWaySpan, kNumSlots,
              iters, warmup, repeats);
  std::printf("# regionA @ +0x%llx slot=%u   regionB @ +0x%llx slot=%u\n",
              (unsigned long long)ofsA, slot_of(buf_addr + ofsA),
              (unsigned long long)ofsB, slot_of(buf_addr + ofsB));

  // ---------------------------------------------------------------------
  // Points.
  // ---------------------------------------------------------------------
  std::vector<Point> points;
  if (sweep == "stride") {
    static const uint32_t kStrides[] = {
      0, 4, 64, 256, 1024, 4096, 4160, 8192, 8256, 8320, 16384, 16448
    };
    for (uint32_t s : kStrides)
      points.push_back({s, opt_ctrl_stride, lanes});
  } else if (sweep == "ways") {
    for (uint32_t n = 1; n <= lanes; ++n)
      points.push_back({opt_alias_stride, opt_ctrl_stride, n});
  } else {
    points.push_back({opt_alias_stride, opt_ctrl_stride,
                      opt_n_alias < 0 ? lanes : (uint32_t)opt_n_alias});
  }

  std::printf("alias_stride ctrl_stride n_alias  aliased_slots  "
              "cyc_min cyc_med cyc_max  cyc_per_load\n");

  int failures = 0;
  for (const Point& p : points) {
    // How many distinct (bank,set) slots the aliased lanes occupy. When this
    // is 1 and n_alias > NUM_WAYS the set is oversubscribed; the host prints
    // it so the reader never has to trust the arithmetic in the prose.
    std::vector<uint32_t> aslots;
    for (uint32_t l = 0; l < p.n_alias; ++l)
      aslots.push_back(slot_of(buf_addr + ofsA + (uint64_t)l * p.alias_stride));
    std::sort(aslots.begin(), aslots.end());
    aslots.erase(std::unique(aslots.begin(), aslots.end()), aslots.end());

    kernel_arg_t ka;
    std::memset(&ka, 0, sizeof(ka));
    ka.buf_addr     = buf_addr;
    ka.out_addr     = out_addr;
    ka.sink_addr    = sink_addr;
    ka.a_word_ofs   = (uint32_t)(ofsA / 4);
    ka.b_word_ofs   = (uint32_t)(ofsB / 4);
    ka.alias_stride = p.alias_stride;
    ka.ctrl_stride  = p.ctrl_stride;
    ka.n_alias      = p.n_alias;
    ka.iters        = iters;
    ka.warmup       = warmup;

    vx_launch_info_t li;
    std::memset(&li, 0, sizeof(li));
    li.struct_size = sizeof(li);
    li.kernel      = kern;
    li.args_host   = &ka;
    li.args_size   = sizeof(ka);
    li.ndim        = 1;
    // grid_dim MUST be >= NUM_CORES. A smaller grid is accepted by
    // vx_enqueue_launch and then dispatches NOTHING, with no error: the
    // output buffer comes back exactly as it was poisoned. Gate 2 exists
    // because this failure is otherwise completely silent.
    li.grid_dim[0] = opt_grid ? opt_grid : (uint32_t)num_cores;
    li.grid_dim[1] = 1;
    li.grid_dim[2] = 1;
    li.block_dim[0] = opt_block ? opt_block : lanes;  // default: one warp
    li.block_dim[1] = 1;
    li.block_dim[2] = 1;
    li.lmem_size   = 0;

    std::vector<uint64_t> samples;
    for (uint32_t rep = 0; rep < repeats; ++rep) {
      // Poison both outputs so a launch that does nothing cannot masquerade
      // as a measurement of zero.
      std::vector<uint8_t>  poison_out(out_bytes, 0xA5);
      std::vector<uint32_t> poison_sink(sink_bytes / 4, 0xDEADBEEFu);
      vx_event_h we0 = nullptr, we1 = nullptr;
      CHECK(vx_enqueue_write(queue, out_b, 0, poison_out.data(), out_bytes,
                             0, nullptr, &we0));
      CHECK(vx_enqueue_write(queue, sink_b, 0, poison_sink.data(), sink_bytes,
                             0, nullptr, &we1));
      CHECK(vx_event_wait_value(we0, 1, VX_TIMEOUT_INFINITE));
      CHECK(vx_event_wait_value(we1, 1, VX_TIMEOUT_INFINITE));

      vx_event_h lev = nullptr, rev = nullptr, sev = nullptr;
      std::vector<probe_result_t> res(STRIDE_PROBE_SLOTS);
      std::vector<uint32_t>       sink(sink_bytes / 4);
      CHECK(vx_enqueue_launch(queue, &li, 0, nullptr, &lev));
      CHECK(vx_enqueue_read(queue, res.data(), out_b, 0, out_bytes, 1, &lev, &rev));
      CHECK(vx_enqueue_read(queue, sink.data(), sink_b, 0, sink_bytes, 1, &lev, &sev));
      CHECK(vx_event_wait_value(rev, 1, VX_TIMEOUT_INFINITE));
      CHECK(vx_event_wait_value(sev, 1, VX_TIMEOUT_INFINITE));

      // GATE 2 -- the kernel ran and was built against THIS header.
      int slot = -1;
      for (int s = 0; s < STRIDE_PROBE_SLOTS; ++s)
        if (res[s].abi == STRIDE_PROBE_ABI) { slot = s; break; }
      if (slot < 0) {
        std::printf("  out[0..3].abi  = %08x %08x %08x %08x  (0xa5a5a5a5 = poison, untouched)\n",
                    res[0].abi, res[1].abi, res[2].abi, res[3].abi);
        std::printf("  sink[0..3]     = %08x %08x %08x %08x  (0xdeadbeef = poison, untouched)\n",
                    sink[0], sink[1], sink[2], sink[3]);
        std::printf("  grid_dim=%u block_dim=%u num_cores=%llu\n",
                    li.grid_dim[0], li.block_dim[0], (unsigned long long)num_cores);
        FATAL("no result slot carries ABI 0x%08x. kernel.vxbin is stale or the "
              "launch did not run. Rebuild: make clean && make\n",
              STRIDE_PROBE_ABI);
      }

      // GATE 3 -- the hardware the kernel saw is the shape asked for.
      const probe_result_t& r = res[slot];
      if (r.num_threads != num_threads || r.num_warps != num_warps ||
          r.num_cores != num_cores)
        FATAL("kernel CSRs report c%uw%ut%u, host caps report c%lluw%llut%llu\n",
              r.num_cores, r.num_warps, r.num_threads,
              (unsigned long long)num_cores, (unsigned long long)num_warps,
              (unsigned long long)num_threads);

      // GATE 4 -- every lane was active for the whole timed region.
      if (r.active_lanes != lanes)
        FATAL("only %u of %u lanes active in the timed region -- the warp "
              "diverged and the measurement is not warp-wide\n",
              r.active_lanes, lanes);

      // GATE 5 -- the stride reached the ADDRESS STREAM, not just the
      // argument struct. The chain is self-referencing, so lane L can only
      // finish where it started if every one of its loads hit the intended
      // address. This is the check that distinguishes "the stride changed the
      // addresses" from "the stride changed a number nothing read".
      for (uint32_t l = 0; l < lanes; ++l) {
        const bool alias = (l < p.n_alias);
        const uint64_t ofs = alias ? ofsA : ofsB;
        const uint32_t st  = alias ? p.alias_stride : p.ctrl_stride;
        const uint32_t want = (uint32_t)((ofs / 4) + (uint64_t)l * (st / 4));
        const uint32_t got  = sink[(uint32_t)slot * STRIDE_PROBE_LANES + l];
        if (got != want)
          FATAL("lane %u ended at word 0x%08x, expected 0x%08x "
                "(alias_stride=%u ctrl_stride=%u n_alias=%u)\n",
                l, got, want, p.alias_stride, p.ctrl_stride, p.n_alias);
      }

      samples.push_back(((uint64_t)r.cycles_hi << 32) | r.cycles_lo);
    }

    std::sort(samples.begin(), samples.end());
    const uint64_t lo  = samples.front();
    const uint64_t med = samples[samples.size() / 2];
    const uint64_t hi  = samples.back();
    std::printf("%12u %11u %7u %14zu  %7llu %7llu %7llu  %12.2f\n",
                p.alias_stride, p.ctrl_stride, p.n_alias, aslots.size(),
                (unsigned long long)lo, (unsigned long long)med,
                (unsigned long long)hi, (double)med / (double)iters);
  }

  CHECK(vx_queue_release(queue));
  CHECK(vx_kernel_release(kern));
  CHECK(vx_module_release(mod));
  CHECK(vx_buffer_release(buf_b));
  CHECK(vx_buffer_release(out_b));
  CHECK(vx_buffer_release(sink_b));
  CHECK(vx_device_release(dev));
  std::printf("PASSED\n");
  return failures;
}
