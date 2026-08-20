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

    wire [NUM_LANES-1:0][`VX_CFG_XLEN-1:0] xr_result;
    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_xr
        wire [31:0] v = execute_if.data.rs1_data[i][31:0]
                      ^ execute_if.data.rs2_data[i][31:0];
        assign xr_result[i] = `VX_CFG_XLEN'((v << shamt) | (v >> lshamt));
    end

    wire [NUM_LANES-1:0][`VX_CFG_XLEN-1:0] unit_result;
    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_sel
        assign unit_result[i] = is_xr ? xr_result[i] : rot_result[i];
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
