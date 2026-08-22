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

`ifdef VX_CFG_EXT_AUTH_POLY_STEP16_ENABLE
    // poly4.step.sg16 rd, rs1(h), rs2(r), rs3(m)
    //
    // One aligned sixteen-lane subgroup absorbs a whole 64-byte ChaCha block --
    // four Poly1305 blocks -- and returns the new accumulator in lanes 0..4.
    //
    //   lanes 0..4 : h0..h4 (rs1) and r0..r4 (rs2), five 26-bit limbs each
    //   lanes 0..15: one message word each (rs3)
    //
    // The r^2, r^3, r^4 schedule the software block-parallel form needs never
    // becomes architectural. That is the whole point of the instruction:
    // measured on the s3f_norp diagnostic, holding it in registers costs twenty
    // loads per 64-byte block and 36% of the kernel's cycles, and it is not
    // part of Poly1305's state -- only of one way of computing it.
    //
    // Timing. Four 130-bit modular multiplies cannot be combinational here: the
    // ChaCha S2 engine's first version was, and missed by 2.752 ns. This walks
    // one output limb per cycle, seven cycles per block, twenty-eight in total.
    // The trick that makes one limb per cycle enough is that the carry chain
    // runs d0 -> d1 -> ... -> d4 in one direction, so the machine needs the
    // running carry and not five 57-bit partial products at once.
    if ((NUM_LANES % 16) != 0) begin : g_sg16_guard
        VX_auth_poly_step16_requires_NUM_LANES_multiple_of_16 __config_error();
    end
    localparam NSG   = (NUM_LANES >= 16) ? (NUM_LANES / 16) : 1;
    localparam LIMB  = 26;
    localparam MASK  = 32'h03ffffff;

    wire is_step16 = (execute_if.data.op_type == INST_OP_BITS'(INST_AUTH_POLY_STEP16));

    // step 0     absorb h + m for this block
    // step 1..5  one output limb each, carry running forward
    // step 6     fold the carry out of d4 back into limb 0 and renormalise
    // step 7     settle. The result buffer samples p_h combinationally, and
    //            step 6's write lands on the same clock edge that would have
    //            retired the instruction -- without this the buffer captures
    //            the accumulator one update early, which it did: every limb of
    //            every trial came back wrong and unmasked.
    localparam SW = 5;
    reg [SW-1:0] p_step;
    wire p_last_in_block = (p_step == SW'(7));

    // Owner lock, for the same reason as VX_sym_chacha_sg16: thirty-two cycles
    // is long enough for the dispatcher to present another warp, and advancing
    // on it would finish one warp's accumulator with another's message.
    reg [`VX_CFG_NUM_WARPS > 1 ? $clog2(`VX_CFG_NUM_WARPS)-1 : 0:0] p_wid;
    wire [`VX_CFG_NUM_WARPS > 1 ? $clog2(`VX_CFG_NUM_WARPS)-1 : 0:0] p_cur_wid =
        execute_if.data.header.wid;
    wire p_idle = (p_step == '0) && (p_blk == 2'd0);
    wire p_mine = p_idle || (p_cur_wid == p_wid);
    reg [1:0] p_blk;
    wire p_last = p_last_in_block && (p_blk == 2'd3);

    reg [NSG-1:0][4:0][31:0] p_h;   // accumulator, five limbs
    reg [NSG-1:0][4:0][31:0] p_a;   // h + m for the block in flight
    reg [NSG-1:0][31:0]      p_c;   // running carry between limbs

    wire [NSG-1:0][4:0][31:0] p_r;
    for (genvar g = 0; g < NSG; ++g) begin : g_r
        for (genvar c = 0; c < 5; ++c) begin : g_rl
            assign p_r[g][c] = execute_if.data.rs2_data[g*16 + c][31:0] & MASK;
        end
    end

    // The five products for the limb in flight. Output limb i takes
    // a[j] * r[i-j] for j <= i and a[j] * 5*r[5+i-j] for j > i, the factor five
    // being the reduction of 2^130 == 5.
    wire [2:0] p_i = p_step[2:0] - 3'd1;
    wire [NSG-1:0][57:0] p_d;
    for (genvar g = 0; g < NSG; ++g) begin : g_d
        wire [57:0] terms [5];
        for (genvar j = 0; j < 5; ++j) begin : g_t
            // j == 0 never wraps -- a[0] always multiplies r[i] -- so this
            // comparison is constant there and Verilator is right to say so.
            /* verilator lint_off UNSIGNED */
            wire [2:0] k    = (p_i >= 3'(j)) ? (p_i - 3'(j)) : (p_i + 3'd5 - 3'(j));
            wire       wrap = (p_i < 3'(j));
            /* verilator lint_on UNSIGNED */
            wire [31:0] rk  = p_r[g][k];
            wire [57:0] prd = 58'(p_a[g][j] * rk);
            assign terms[j] = wrap ? (prd + {prd[55:0], 2'b0}) : prd;  // x5 == x1 + x4
        end
        assign p_d[g] = terms[0] + terms[1] + terms[2] + terms[3] + terms[4]
                      + 58'(p_c[g]);
    end

    always @(posedge clk) begin
        if (reset) begin
            p_step <= '0;
            p_blk  <= '0;
        end else if (execute_if.valid && eb_ready && is_step16 && p_mine) begin
            p_step <= p_last_in_block ? '0 : (p_step + SW'(1));
            if (p_idle) p_wid <= p_cur_wid;
            if (p_last_in_block) begin
                p_blk <= p_last ? 2'd0 : (p_blk + 2'd1);
            end
            for (int g = 0; g < NSG; ++g) begin
                if (execute_if.data.header.tmask[g*16]) begin
                    if (p_step == SW'(0)) begin
                        // Absorb, with the 0x01 byte a full block always
                        // carries. The first block starts from rs1, later ones
                        // from what the previous block left.
                        automatic logic [4:0][31:0] hh =
                            (p_blk == 2'd0) ? '{execute_if.data.rs1_data[g*16+4][31:0] & MASK,
                                                execute_if.data.rs1_data[g*16+3][31:0] & MASK,
                                                execute_if.data.rs1_data[g*16+2][31:0] & MASK,
                                                execute_if.data.rs1_data[g*16+1][31:0] & MASK,
                                                execute_if.data.rs1_data[g*16+0][31:0] & MASK}
                                            : p_h[g];
                        automatic logic [31:0] t0 = execute_if.data.rs3_data[g*16 + 32'({p_blk, 2'd0})][31:0];
                        automatic logic [31:0] t1 = execute_if.data.rs3_data[g*16 + 32'({p_blk, 2'd1})][31:0];
                        automatic logic [31:0] t2 = execute_if.data.rs3_data[g*16 + 32'({p_blk, 2'd2})][31:0];
                        automatic logic [31:0] t3 = execute_if.data.rs3_data[g*16 + 32'({p_blk, 2'd3})][31:0];
                        p_a[g][0] <= hh[0] + (t0 & MASK);
                        p_a[g][1] <= hh[1] + (((t0 >> 26) | (t1 << 6)) & MASK);
                        p_a[g][2] <= hh[2] + (((t1 >> 20) | (t2 << 12)) & MASK);
                        p_a[g][3] <= hh[3] + (((t2 >> 14) | (t3 << 18)) & MASK);
                        p_a[g][4] <= hh[4] + ((t3 >> 8) | 32'h01000000);
                        p_c[g] <= '0;
                    end else if (p_step == SW'(7)) begin
                        // settle
                    end else if (p_step <= SW'(5)) begin
                        p_h[g][p_i] <= 32'(p_d[g][25:0]);
                        p_c[g]      <= 32'(p_d[g][57:LIMB]);
                    end else begin
                        // h0 += 5*c, then one more carry into h1.
                        automatic logic [31:0] n0 = p_h[g][0] + (p_c[g] + {p_c[g][29:0], 2'b0});
                        p_h[g][0] <= n0 & MASK;
                        p_h[g][1] <= p_h[g][1] + (n0 >> LIMB);
                    end
                end
            end
        end
    end

    wire [NUM_LANES-1:0][XLEN-1:0] step16_result;
    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_s16
        localparam int G = i / 16;
        localparam int C = i % 16;
        assign step16_result[i] = (C < 5) ? XLEN'(p_h[G][C]) : XLEN'(0);
    end

`ifdef SIMULATION
    for (genvar g = 0; g < NSG; ++g) begin : g_sg16_chk
        wire [15:0] gm = execute_if.data.header.tmask[g*16 +: 16];
        `RUNTIME_ASSERT(!(execute_if.valid && is_step16)
                        || (gm == 16'h0000) || (gm == 16'hffff),
            ("poly4.step.sg16 on a partially active subgroup: g=%0d, mask=%b -- all sixteen lanes must be active",
                g, gm))
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
        wire [XLEN-1:0] mac_result = XLEN'(execute_if.data.rs1_data[i][31:0] + part);
`ifdef VX_CFG_EXT_AUTH_POLY_SG4_ENABLE
        wire [XLEN-1:0] sel_rsum = is_rsum ? rsum_result[i] : mac_result;
`else
        wire [XLEN-1:0] sel_rsum = mac_result;
`endif
`ifdef VX_CFG_EXT_AUTH_POLY_STEP16_ENABLE
        assign poly_result[i] = is_step16 ? step16_result[i] : sel_rsum;
`else
        assign poly_result[i] = sel_rsum;
`endif
    end

    // The sixteen-lane macro-op occupies the unit for twenty-eight cycles and
    // must not retire until the last one; everything else is a single cycle.
`ifdef VX_CFG_EXT_AUTH_POLY_STEP16_ENABLE
    wire unit_done = ~is_step16 | (p_last && p_mine);
`else
    wire unit_done = 1'b1;
`endif
    wire eb_ready;
    assign execute_if.ready = eb_ready && unit_done;

    VX_elastic_buffer #(
        .DATAW ($bits(auth_header_t) + (NUM_LANES * XLEN))
    ) rsp_buf (
        .clk       (clk),
        .reset     (reset),
        .valid_in  (execute_if.valid && unit_done),
        .ready_in  (eb_ready),
        .data_in   ({execute_if.data.header, poly_result}),
        .data_out  ({result_if.data.header,  result_if.data.data}),
        .valid_out (result_if.valid),
        .ready_out (result_if.ready)
    );

endmodule
