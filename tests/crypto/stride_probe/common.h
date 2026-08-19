#ifndef _COMMON_H_
#define _COMMON_H_

// Warp-wide strided-access cost probe.
//
// Measures one thing: what a single warp-wide load costs when the lanes of the
// warp are spaced `alias_stride` bytes apart. Nothing about the platform is
// modified -- this is an ordinary kernel over an ordinary device buffer that
// reproduces the ADDRESS SHAPE of an sp-relative access without touching
// vx_start.S, the stack, or any shared configuration.
//
// The addressing under test:
//
//   lane L walks a one-node self-referencing chain at
//       region_A + L * alias_stride      for L <  n_alias
//       region_B + L * ctrl_stride       for L >= n_alias
//
// Every value in this struct is a RUNTIME argument. The compiled kernel is
// byte-identical for every point in a sweep, so the layout sensitivity that
// bounds every other measurement in this project (docs/proposals/
// crypto_isa_proposal.md sections 16.4 and 18.2) cannot act here: there is no
// code difference between the points being compared.

#define STRIDE_PROBE_ABI   0x50524231u  // 'PRB1' -- bump on any struct change
#define STRIDE_PROBE_LANES 64           // max lanes recorded (>= VX_CFG_NUM_THREADS)
#define STRIDE_PROBE_SLOTS 64           // max (core, warp) result slots

typedef struct {
  uint64_t buf_addr;     // base of the chain buffer, prefilled with buf[i] = i
  uint64_t out_addr;     // probe_result_t[STRIDE_PROBE_SLOTS]
  uint64_t sink_addr;    // uint32_t[STRIDE_PROBE_SLOTS * STRIDE_PROBE_LANES]
  uint32_t a_word_ofs;   // region A base, in words, from buf_addr
  uint32_t b_word_ofs;   // region B base, in words, from buf_addr
  uint32_t alias_stride; // bytes between lanes in region A (multiple of 4)
  uint32_t ctrl_stride;  // bytes between lanes in region B (multiple of 4)
  uint32_t n_alias;      // how many lanes use region A
  uint32_t iters;        // timed dependent loads per lane
  uint32_t warmup;       // untimed dependent loads per lane
  uint32_t pad;
} kernel_arg_t;

typedef struct {
  uint32_t abi;          // == STRIDE_PROBE_ABI; proves this slot was written
                         // by a kernel built against THIS header
  uint32_t cycles_lo;
  uint32_t cycles_hi;
  uint32_t num_threads;  // VX_CSR_NUM_THREADS -- read from the hardware
  uint32_t num_warps;    // VX_CSR_NUM_WARPS
  uint32_t num_cores;    // VX_CSR_NUM_CORES
  uint32_t hart_id;      // VX_CSR_MHARTID of the recording lane
  uint32_t active_lanes; // popcount(VX_CSR_ACTIVE_THREADS) in the timed region
} probe_result_t;

#endif
