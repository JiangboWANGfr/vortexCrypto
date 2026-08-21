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

`ifdef VX_CFG_EXT_AUTH_POLY_SG4_ENABLE
    // poly26.rsum.sg4: the four partial sums of the block-parallel form folded
    // into every lane at once. A butterfly of two shuffles and two adds per
    // limb becomes one instruction, and because every lane receives the total,
    // the serial parts of the AEAD afterwards need no broadcast.
    //
    // PRECONDITION: the quad must be converged; the source lanes' masks are not
    // consulted, as for aesrm.sg4 and ghmul.sg4.
    //
    // Software must present limbs already normalised below 2^26 -- four of them
    // then sum below 2^28 and the 32-bit result cannot wrap. That is a stated
    // precondition rather than hardware behaviour: the accumulators the
    // multiply leaves behind reach 2^30.4 and four of THOSE would overflow.
    if ((NUM_LANES < 4) || ((NUM_LANES % 4) != 0)) begin : g_sg4_guard
        VX_auth_poly_sg4_requires_NUM_LANES_multiple_of_4 __config_error();
    end
    wire is_rsum = (execute_if.data.op_type == INST_OP_BITS'(INST_AUTH_POLY_RSUM));

    // Same rule as the subgroup ops in VX_sym_rot: a quad's thread mask must be
    // uniform, and an inactive lane contributes zero rather than whatever the
    // register file last left in its rs1. Summing an unmasked neighbour reads a
    // stale limb into the accumulator, which is silent -- a Poly1305 tag is
    // uniformly random-looking whether it is right or wrong.
    wire [NUM_LANES-1:0][XLEN-1:0] rsum_result;
    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_rsum
        localparam int Q = (i / 4) * 4;
        wire [31:0] t [4];
        for (genvar k = 0; k < 4; ++k) begin : g_term
            assign t[k] = execute_if.data.header.tmask[Q+k]
                        ? execute_if.data.rs1_data[Q+k][31:0] : 32'b0;
        end
        assign rsum_result[i] = XLEN'(t[0] + t[1] + t[2] + t[3]);
    end

`ifdef SIMULATION
    for (genvar q = 0; q < NUM_LANES / 4; ++q) begin : g_quad_chk
        wire [3:0] qm = execute_if.data.header.tmask[q*4 +: 4];
        `RUNTIME_ASSERT(!(execute_if.valid && is_rsum) || (qm == 4'b0000) || (qm == 4'b1111),
            ("poly26.rsum.sg4 on a partially active quad: q=%0d, mask=%b, tmask=%b -- a quad's thread mask must be uniform",
                q, qm, execute_if.data.header.tmask))
    end
`endif
`endif

    wire [NUM_LANES-1:0][XLEN-1:0] poly_result;

    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_lanes
        wire [25:0] rlimb = execute_if.data.rs3_data[i][25:0];
        wire [57:0] prod  = execute_if.data.rs2_data[i][31:0] * rlimb;
        // 5*p is p + 4*p, two shifted adds rather than a second multiplier.
        wire [60:0] scaled = is_scale5 ? ({3'b0, prod} + {1'b0, prod, 2'b0})
                                       : {3'b0, prod};
        wire [31:0] part = is_high ? scaled[57:26] : {6'b0, scaled[25:0]};
`ifdef VX_CFG_EXT_AUTH_POLY_SG4_ENABLE
        assign poly_result[i] = is_rsum ? rsum_result[i]
                              : XLEN'(execute_if.data.rs1_data[i][31:0] + part);
`else
        assign poly_result[i] = XLEN'(execute_if.data.rs1_data[i][31:0] + part);
`endif
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
