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

// Poly1305 processing element: a three-source multiply-accumulate on the
// 26-bit limbs the software already uses.
//
//   poly26.macl  rd, rs1, rs2, rs3   rd = rs1 + ((rs2 * r) & 0x3ffffff)
//   poly26.mach  rd, rs1, rs2, rs3   rd = rs1 + ((rs2 * r) >> 26)
//   poly26.macl5 rd, rs1, rs2, rs3   the same with 5*(rs2 * r)
//   poly26.mach5 rd, rs1, rs2, rs3   likewise
//
// where r = rs3 & 0x3ffffff.
//
// Poly1305's block update is a 5x5 convolution of the accumulator's limbs with
// the key's, and the wrapped terms carry a factor of five from the reduction
// modulo 2^130-5. Software normally precomputes s_i = 5*r_i to avoid the
// multiply -- but s_i is up to 2^28.3 and does not fit a 26-bit limb, so the
// scale5 forms exist to let the key stay in five registers instead of nine.
// That matters here: the ChaCha20-Poly1305 kernel spills, and four fewer live
// values is four fewer spill slots.
//
// The low and high halves accumulate separately and are recombined once per
// output limb. That is exact, not approximate: the low accumulator sums the
// products modulo 2^26 and the high one sums their quotients, so their
// weighted sum is the true convolution. With five products the low accumulator
// stays under 2^28.4 and the high one under 2^30.4, both inside 32 bits.
//
// Three sources cost nothing new on this machine: the operand collector already
// fetches rs3 for WGATHER and the scoreboard already tracks it. Fixed one
// cycle, combinational plus a single elastic buffer.

module VX_auth_poly import VX_gpu_pkg::*; #(
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

    localparam XLEN = `VX_CFG_XLEN;

    // funct2 = {scale5, high_part}
    wire is_high   = execute_if.data.op_args.sym.bs[0];
    wire is_scale5 = execute_if.data.op_args.sym.bs[1];

    wire [NUM_LANES-1:0][XLEN-1:0] poly_result;

    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_lanes
        wire [25:0] rlimb = execute_if.data.rs3_data[i][25:0];
        wire [57:0] prod  = execute_if.data.rs2_data[i][31:0] * rlimb;
        // 5*p is p + 4*p, two shifted adds rather than a second multiplier.
        wire [60:0] scaled = is_scale5 ? ({3'b0, prod} + {1'b0, prod, 2'b0})
                                       : {3'b0, prod};
        wire [31:0] part = is_high ? scaled[57:26] : {6'b0, scaled[25:0]};
        assign poly_result[i] = XLEN'(execute_if.data.rs1_data[i][31:0] + part);
    end

    VX_elastic_buffer #(
        .DATAW ($bits(auth_header_t) + (NUM_LANES * XLEN))
    ) rsp_buf (
        .clk       (clk),
        .reset     (reset),
        .valid_in  (execute_if.valid),
        .ready_in  (execute_if.ready),
        .data_in   ({execute_if.data.header, poly_result}),
        .data_out  ({result_if.data.header,  result_if.data.data}),
        .valid_out (result_if.valid),
        .ready_out (result_if.ready)
    );

endmodule
