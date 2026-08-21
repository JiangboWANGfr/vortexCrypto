// Copyright © 2019-2023
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

`include "VX_define.vh"

// Rotate processing element: the ratified RISC-V Zbb/Zbkb rotate-immediate.
//
//   RORI rd, rs1, shamt   rd = (rs1 >> shamt) | (rs1 << (32 - shamt))
//
// This is not a cryptographic transform and carries no S-box, no field
// arithmetic and no algorithm-specific constant. It is here because ChaCha20's
// quarter-round is add/xor/rotate and rv32imaf has no rotate at all, so the
// software baseline pays slli+srli+or for every one of them. Implementing it
// raises that baseline; it is not part of any cryptographic instruction-set
// extension and a speedup measured against a baseline without it would be
// claiming credit for the B extension.
//
// 1R1W and fixed one cycle, combinational plus a single elastic buffer, so
// execute_if.ready is never held low for more than one cycle: this unit cannot
// head-of-line block anything behind it. Only the immediate form is
// implemented; ChaCha20's four rotate amounts are compile-time constants, so
// the register forms ROL/ROR would have no user here.

module VX_sym_rot import VX_gpu_pkg::*; #(
    parameter `STRING INSTANCE_ID = "",
    parameter NUM_LANES = 1
) (
    input wire              clk,
    input wire              reset,

    // Inputs
    VX_execute_if.slave     execute_if,

    // Outputs
    VX_result_if.master     result_if
);
    `UNUSED_SPARAM (INSTANCE_ID)

    // The 5-bit shamt is the RV32 encoding; RV64 RORI takes six bits and moves
    // the funct7 boundary, so the decode arm that feeds this would be wrong.
    // Guard rather than silently rotating by a truncated amount.
    `STATIC_ASSERT (`VX_CFG_XLEN == 32, ("VX_sym_rot: RORI here is the RV32 5-bit-shamt form"))

    wire [4:0] shamt = execute_if.data.op_args.sym.shamt;

    // Left amount is -shamt taken modulo 32, which is what makes shamt == 0
    // fall out as a plain copy without a special case.
    wire [4:0] lshamt = 5'd0 - shamt;

    wire [NUM_LANES-1:0][`VX_CFG_XLEN-1:0] rot_result;

    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_lanes
        wire [31:0] x = execute_if.data.rs1_data[i][31:0];
        assign rot_result[i] = `VX_CFG_XLEN'((x >> shamt) | (x << lshamt));
    end

`ifdef VX_CFG_EXT_SYM_CHACHA_ENABLE
    // ChaCha20's quarter-round never rotates without xoring first:
    //
    //   d ^= a; d <<<= 16;   b ^= c; b <<<= 12;
    //   d ^= a; d <<<=  8;   b ^= c; b <<<=  7;
    //
    // so the two always travel together and the pair costs two instructions
    // where the shifter is idle for one of them. Fusing them is the whole
    // extension: no S-box, no field arithmetic, no algorithm constant, just the
    // XOR the shifter's input always has in front of it.
    //
    // shamt here is the LEFT amount, unlike RORI's right amount in the same
    // field, because ChaCha specifies left rotates. Negating gives the other
    // direction for free, exactly as it does above, and shamt == 0 falls out as
    // a plain XOR without a special case.
    wire is_xr = (execute_if.data.op_type == INST_OP_BITS'(INST_SYM_CHACHA_XR));

    // funct7[5] routes rs2 from the next lane of the aligned quad. ChaCha's
    // diagonal round reads ALL EIGHT of its operands from lane +1 -- the D
    // owner is lane j+3 and reads A from lane j, and -3 == +1 mod 4 -- so one
    // direction covers the whole round and the source index is a constant
    // permutation within a four-block, which synthesises to wires.
    //
    // PRECONDITION, as for aesrm.sg4: the quad must be converged. The source
    // lane's mask is not consulted, deliberately, so that the two models cannot
    // disagree the way SHFL does.
`ifdef VX_CFG_EXT_SYM_CHACHA_SG4_ENABLE
    if ((NUM_LANES < 4) || ((NUM_LANES % 4) != 0)) begin : g_sg4_guard
        VX_sym_rot_sg4_requires_NUM_LANES_multiple_of_4 __config_error();
    end
    wire route = execute_if.data.op_args.sym.bs[0];
    wire is_chadd = (execute_if.data.op_type == INST_OP_BITS'(INST_SYM_CHADD_SG4));
`else
    wire route = 1'b0;
    wire is_chadd = 1'b0;
    `UNUSED_VAR (execute_if.data.op_args.sym.bs)
`endif

    // A subgroup instruction reads a neighbour's register. An inactive lane's
    // rs2_data is whatever the register file last left there, so reading it
    // without consulting the mask returns a stale value and computes a wrong
    // answer with nothing to show for it. The architectural rule is that a
    // quad's mask is uniform -- all four lanes or none -- and the assertion
    // below catches a violation in simulation. The mask on the read is what
    // makes the hardware deterministic if one ever reaches silicon: a masked
    // neighbour contributes zero rather than a leftover.
    wire [NUM_LANES-1:0][`VX_CFG_XLEN-1:0] xr_result;
    wire [NUM_LANES-1:0][`VX_CFG_XLEN-1:0] add_result;
    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_xr
        localparam int NEXT = ((i / 4) * 4) + ((i + 1) % 4);
        localparam int SRC  = (NUM_LANES >= 4) ? NEXT : i;
        wire [31:0] rs2_local = execute_if.data.rs2_data[i][31:0];
        wire [31:0] rs2_next  = execute_if.data.header.tmask[SRC]
                              ? execute_if.data.rs2_data[SRC][31:0] : 32'b0;
        wire [31:0] rs2_sel   = route ? rs2_next : rs2_local;
        wire [31:0] v = execute_if.data.rs1_data[i][31:0] ^ rs2_sel;
        assign xr_result[i]  = `VX_CFG_XLEN'((v << shamt) | (v >> lshamt));
        assign add_result[i] = `VX_CFG_XLEN'(execute_if.data.rs1_data[i][31:0] + rs2_next);
    end

`ifdef SIMULATION
    // Fires on the instruction that would read across a torn quad, not on the
    // divergence itself: a warp is free to diverge, it just may not issue a
    // subgroup instruction while it has.
    wire sg4_active = execute_if.valid && (is_chadd || (is_xr && route));
    for (genvar q = 0; q < NUM_LANES / 4; ++q) begin : g_quad_chk
        wire [3:0] qm = execute_if.data.header.tmask[q*4 +: 4];
        `RUNTIME_ASSERT(!sg4_active || (qm == 4'b0000) || (qm == 4'b1111),
            ("subgroup op on a partially active quad: q=%0d, mask=%b, tmask=%b -- a quad's thread mask must be uniform",
                q, qm, execute_if.data.header.tmask))
    end
`endif

    wire [NUM_LANES-1:0][`VX_CFG_XLEN-1:0] unit_result;
    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_sel
        assign unit_result[i] = is_chadd ? add_result[i]
                              : (is_xr ? xr_result[i] : rot_result[i]);
    end
`else
    wire [NUM_LANES-1:0][`VX_CFG_XLEN-1:0] unit_result = rot_result;
    `UNUSED_VAR (execute_if.data.rs2_data)
`endif

    `UNUSED_VAR (execute_if.data.rs3_data)

    VX_elastic_buffer #(
        .DATAW ($bits(sym_header_t) + (NUM_LANES * `VX_CFG_XLEN))
    ) rsp_buf (
        .clk       (clk),
        .reset     (reset),
        .valid_in  (execute_if.valid),
        .ready_in  (execute_if.ready),
        .data_in   ({execute_if.data.header,  unit_result}),
        .data_out  ({result_if.data.header,   result_if.data.data}),
        .valid_out (result_if.valid),
        .ready_out (result_if.ready)
    );

endmodule
