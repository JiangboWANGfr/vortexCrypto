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

    `UNUSED_VAR (execute_if.data.rs2_data)
    `UNUSED_VAR (execute_if.data.rs3_data)

    VX_elastic_buffer #(
        .DATAW ($bits(sym_header_t) + (NUM_LANES * `VX_CFG_XLEN))
    ) rsp_buf (
        .clk       (clk),
        .reset     (reset),
        .valid_in  (execute_if.valid),
        .ready_in  (execute_if.ready),
        .data_in   ({execute_if.data.header,  rot_result}),
        .data_out  ({result_if.data.header,   result_if.data.data}),
        .valid_out (result_if.valid),
        .ready_out (result_if.ready)
    );

endmodule
