#include <vx_spawn2.h>
#include <vx_intrinsics.h>
#include "common.h"

// One warp, one dependent load chain per lane, one timed region.
//
// Each lane owns a SINGLE word and loads it `iters` times. The word is
// self-referencing (the host prefills buf[i] = i), so the address of iteration
// k+1 is the value loaded at iteration k: a true data dependence. The compiler
// cannot hoist it, the LSU cannot overlap successive iterations, and no
// prefetcher can run ahead of it. What is left in the timed region is the
// steady-state cost of one warp-wide load at the chosen lane spacing.
//
// Because the word is re-touched every iteration, the measurement is a pure
// residency question. At a spacing that gives each lane a distinct D-cache set
// the line stays resident and every iteration hits. At a spacing that is a
// multiple of the way span (VX_CFG_DCACHE_SIZE / VX_CFG_DCACHE_NUM_WAYS =
// 16384 / 4 = 4096 B) every lane lands on the SAME set, and once more than
// VX_CFG_DCACHE_NUM_WAYS lanes do so the set thrashes under FIFO replacement
// and every iteration misses.
//
// The two regions exist so that lane count, instruction count and issued-load
// count are IDENTICAL for every value of n_alias. Only the number of lanes
// sharing one set varies. A cost that is flat to n_alias = NUM_WAYS and then
// climbs is the signature of set associativity and of nothing else; a cost that
// climbs from n_alias = 1 is ordinary traffic and refutes the account.

__kernel void stride_probe(kernel_arg_t* __UNIFORM__ arg) {
  const uint32_t lane = (uint32_t)vx_thread_id();

  uint32_t* const buf = (uint32_t*)(uintptr_t)arg->buf_addr;

  // Branchless lane classification: with +zicond (set in
  // tests/regression/common.mk) these become czero selects, so the warp does
  // not diverge and the timed region is entered with the full lane mask.
  const bool alias    = (lane < arg->n_alias);
  const uint32_t base = alias ? arg->a_word_ofs : arg->b_word_ofs;
  const uint32_t stw  = (alias ? arg->alias_stride : arg->ctrl_stride) >> 2;

  uint32_t idx = base + lane * stw;
  const uint32_t idx0 = idx;

  // Untimed: reach steady state (first-touch fills, DRAM row opens).
  for (uint32_t i = 0; i < arg->warmup; ++i) {
    idx = buf[idx];
  }

  // Timed. vx_rdcycle_sync_{begin,end} issue a wsync first, so the timestamps
  // bracket the whole warp rather than one lane's view of it.
  const size_t mask = vx_active_threads();
  __rdcycle_time t0 = vx_rdcycle_sync_begin();
  #pragma clang loop unroll(disable)
  for (uint32_t i = 0; i < arg->iters; ++i) {
    idx = buf[idx];
  }
  __rdcycle_time t1 = vx_rdcycle_sync_end();

  const uint32_t slot = (uint32_t)vx_core_id() * (uint32_t)vx_num_warps()
                      + (uint32_t)vx_warp_id();

  // Per-lane sink. The chain is self-referencing, so a lane that touched the
  // addresses the host laid out MUST end where it started. The host checks
  // every lane against idx0 computed independently on its side; a mismatch
  // means the stride did not reach the address stream and the run is rejected.
  uint32_t* sink = (uint32_t*)(uintptr_t)arg->sink_addr;
  if (slot < STRIDE_PROBE_SLOTS && lane < STRIDE_PROBE_LANES) {
    sink[slot * STRIDE_PROBE_LANES + lane] = idx;
  }
  (void)idx0;

  if (lane == 0 && slot < STRIDE_PROBE_SLOTS) {
    probe_result_t* out = (probe_result_t*)(uintptr_t)arg->out_addr;
    uint64_t d = vx_rdcycle_sync_diff(t0, t1);
    probe_result_t r;
    r.abi          = STRIDE_PROBE_ABI;
    r.cycles_lo    = (uint32_t)d;
    r.cycles_hi    = (uint32_t)(d >> 32);
    r.num_threads  = (uint32_t)vx_num_threads();
    r.num_warps    = (uint32_t)vx_num_warps();
    r.num_cores    = (uint32_t)vx_num_cores();
    r.hart_id      = (uint32_t)vx_hart_id();
    r.active_lanes = (uint32_t)__builtin_popcount((uint32_t)mask);
    out[slot] = r;
  }
}
