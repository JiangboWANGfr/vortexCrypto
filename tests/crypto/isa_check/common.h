#ifndef _COMMON_H_
#define _COMMON_H_

// Instruction-level conformance check for the EX_SYM and EX_AUTH instructions.
//
// This exists because an unimplemented or mis-decoded crypto encoding does not
// trap in this design -- it executes as some other instruction, and RTL and
// simx do not necessarily agree on which. A kernel-level test would only show
// the resulting wrong answer; this shows which instruction is wrong.
//
// The device runs each instruction over a fixed vector table and writes the
// raw results back. The host holds an independent reference implementation and
// compares per instruction, per vector.

#define ISA_NUM_VECTORS 16

// One entry per instruction under test. Order must match kOpNames in main.cpp
// and the switch in kernel.cpp.
#define ISA_OP_CLMUL      0
#define ISA_OP_CLMULH     1
#define ISA_OP_BREV8      2
#define ISA_OP_AES32ESI   3   // uses bs = vector index & 3
#define ISA_OP_AES32ESMI  4
#define ISA_OP_RORI       5   // uses shamt = ChaCha20's four amounts, by index
#define ISA_NUM_OPS       6

#define ISA_NUM_RESULTS (ISA_NUM_OPS * ISA_NUM_VECTORS)

typedef struct {
  uint64_t src_a;      // ISA_NUM_VECTORS words
  uint64_t src_b;      // ISA_NUM_VECTORS words
  uint64_t dst;        // ISA_NUM_RESULTS words
} kernel_arg_t;

#endif
