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

// chacha.dr.sg16 rd, rs1 -- one aligned sixteen-lane subgroup holds one 512-bit
// ChaCha20 state, lane i carrying word i, and one instruction advances a full
// double-round.
//
// Single source, single destination, no hidden context. That is the whole point
// of the design against the S2 engine next door: S2 buys its low load count
// with 57,344 bits of per-(warp, lane) state that a kernel switch must then
// account for; this buys the same with one architectural register per lane.
//
// The two rounds' lane groupings are fixed permutations, not a crossbar:
//
//   column   QR(0,4,8,12) QR(1,5,9,13) QR(2,6,10,14) QR(3,7,11,15)
//   diagonal QR(0,5,10,15) QR(1,6,11,12) QR(2,7,8,13) QR(3,4,9,14)
//
// A lane's role is always its row, i >> 2. Its group is i & 3 in the column
// round and ((i & 3) - (i >> 2)) & 3 in the diagonal one.
//
// Timing: eight quarter-round lines, one per cycle, plus a load and a settle.
// Ten cycles. Not combinational -- the ChaCha S2 engine tried that first and
// missed by 2.752 ns.

module VX_sym_chacha_sg16 import VX_gpu_pkg::*; #(
    parameter `STRING INSTANCE_ID = "",
    parameter NUM_LANES = 1
) (
    input wire              clk,
    input wire              reset,
    VX_execute_if.slave     execute_if,
    VX_result_if.master     result_if
);
    `UNUSED_SPARAM (INSTANCE_ID)
    localparam XLEN = `VX_CFG_XLEN;

    if ((NUM_LANES % 16) != 0) begin : g_sg16_guard
        VX_sym_chacha_sg16_requires_NUM_LANES_multiple_of_16 __config_error();
    end
    localparam NSG = (NUM_LANES >= 16) ? (NUM_LANES / 16) : 1;

    wire is_dr16 = (execute_if.data.op_type == INST_OP_BITS'(INST_SYM_CHA_DR16));

    // step 0     load rs1 into the working state
    // step 1..4  column round, one quarter-round line per cycle
    // step 5..8  diagonal round
    // step 9     settle, so the result buffer samples a written state
    reg [3:0] d_step;
    wire d_last = (d_step == 4'd9);

    // The machine is stateless per instruction but takes ten cycles, and the
    // dispatcher may present a different warp while ready is low. Without an
    // owner the sequence would advance on whoever happens to be at the port and
    // finish with another warp's state -- which it did: subgroup 0 was correct
    // and every later one wrong, because subgroup 0 is warp 0 and the rest are
    // not.
    reg [`VX_CFG_NUM_WARPS > 1 ? $clog2(`VX_CFG_NUM_WARPS)-1 : 0:0] d_wid;
    wire [`VX_CFG_NUM_WARPS > 1 ? $clog2(`VX_CFG_NUM_WARPS)-1 : 0:0] cur_wid =
        execute_if.data.header.wid;
    wire d_idle  = (d_step == 4'd0);
    wire d_mine  = d_idle || (cur_wid == d_wid);

    reg [NSG-1:0][15:0][31:0] xw;

    // The four lane indices of the quarter-round lane i belongs to, in role
    // order a, b, c, d. Round 0 is the column round, round 1 the diagonal.
    function automatic [3:0] qr_member(input [3:0] i, input rnd, input [1:0] role);
        logic [1:0] p, r, g;
        p = i[1:0];
        r = i[3:2];
        g = rnd ? (p - r) : p;
        qr_member = rnd ? {role, ((g + role) & 2'b11)} : {role, g};
    endfunction

    wire       d_rnd  = (d_step > 4'd4);
    wire [1:0] d_line = d_rnd ? 2'(d_step - 4'd5) : 2'(d_step - 4'd1);

    // line 0: a += b; d ^= a; d <<<= 16       line 1: c += d; b ^= c; b <<<= 12
    // line 2: a += b; d ^= a; d <<<= 8        line 3: c += d; b ^= c; b <<<= 7
    wire [4:0] d_rot = (d_line == 2'd0) ? 5'd16
                     : (d_line == 2'd1) ? 5'd12
                     : (d_line == 2'd2) ? 5'd8 : 5'd7;

    wire [NSG-1:0][15:0][31:0] nxt;
    for (genvar g = 0; g < NSG; ++g) begin : g_sg
        for (genvar i = 0; i < 16; ++i) begin : g_ln
            wire [3:0] ia = qr_member(4'(i), d_rnd, 2'd0);
            wire [3:0] ib = qr_member(4'(i), d_rnd, 2'd1);
            wire [3:0] ic = qr_member(4'(i), d_rnd, 2'd2);
            wire [3:0] id = qr_member(4'(i), d_rnd, 2'd3);
            wire [31:0] va = xw[g][ia], vb = xw[g][ib];
            wire [31:0] vc = xw[g][ic], vd = xw[g][id];
            // Lines 0 and 2 update a then d; lines 1 and 3 update c then b.
            wire [31:0] a_n = va + vb;
            wire [31:0] c_n = vc + vd;
            wire [31:0] d_x = vd ^ a_n;
            wire [31:0] b_x = vb ^ c_n;
            wire [31:0] d_n = (d_x << d_rot) | (d_x >> (6'd32 - {1'b0, d_rot}));
            wire [31:0] b_n = (b_x << d_rot) | (b_x >> (6'd32 - {1'b0, d_rot}));
            wire even = (d_line == 2'd0) || (d_line == 2'd2);
            assign nxt[g][i] = (i[3:2] == 2'd0) ? (even ? a_n : xw[g][i])
                             : (i[3:2] == 2'd1) ? (even ? xw[g][i] : b_n)
                             : (i[3:2] == 2'd2) ? (even ? xw[g][i] : c_n)
                                                : (even ? d_n : xw[g][i]);
        end
    end

    wire eb_ready;
    wire fire = execute_if.valid && eb_ready && is_dr16 && d_mine;

    always @(posedge clk) begin
        if (reset) begin
            d_step <= 4'd0;
        end else if (fire) begin
            d_step <= d_last ? 4'd0 : (d_step + 4'd1);
            if (d_idle) d_wid <= cur_wid;
            for (int g = 0; g < NSG; ++g) begin
                if (execute_if.data.header.tmask[g*16]) begin
                    if (d_step == 4'd0) begin
                        for (int i = 0; i < 16; ++i) begin
                            xw[g][i] <= execute_if.data.rs1_data[g*16 + i][31:0];
                        end
                    end else if (d_step <= 4'd8) begin
                        xw[g] <= nxt[g];
                    end
                end
            end
        end
    end

`ifdef SIMULATION
    for (genvar g = 0; g < NSG; ++g) begin : g_sg16_chk
        wire [15:0] gm = execute_if.data.header.tmask[g*16 +: 16];
        `RUNTIME_ASSERT(!(execute_if.valid && is_dr16)
                        || (gm == 16'h0000) || (gm == 16'hffff),
            ("chacha.dr.sg16 on a partially active subgroup: g=%0d, mask=%b -- all sixteen lanes must be active",
                g, gm))
    end
`endif

    wire [NUM_LANES-1:0][XLEN-1:0] dr_result;
    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_out
        localparam int G = i / 16;
        localparam int C = i % 16;
        assign dr_result[i] = XLEN'(xw[G][C]);
    end

    wire unit_done = ~is_dr16 | (d_last && d_mine);
    assign execute_if.ready = eb_ready && unit_done;

    VX_elastic_buffer #(
        .DATAW ($bits(sym_header_t) + (NUM_LANES * XLEN))
    ) rsp_buf (
        .clk       (clk),
        .reset     (reset),
        .valid_in  (execute_if.valid && unit_done),
        .ready_in  (eb_ready),
        .data_in   ({execute_if.data.header, dr_result}),
        .data_out  ({result_if.data.header,  result_if.data.data}),
        .valid_out (result_if.valid),
        .ready_out (result_if.ready)
    );

endmodule
