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

// Stateful per-lane ChaCha20 engine (section 23 of the crypto proposal).
//
// Every lane owns a whole 512-bit ChaCha state in a context keyed by (warp,
// lane) -- keyed by the warp too, because warps interleave and a per-lane
// context alone would be clobbered by whichever issued last. One instruction
// advances a double-round, which is eight quarter-rounds.
//
// A double-round takes EIGHT cycles, one quarter-round per cycle, so the
// arithmetic is one quarter-round wide per lane rather than eight. The unit
// holds execute_if.ready low meanwhile, which is also the whole hazard
// mechanism: these instructions write no architectural register except CRD, so
// the scoreboard cannot order them, and a single global busy interlock is
// enough because the pipeline into this unit is in-order.
//
// The context also holds the key and the nonce, so BEGIN rebuilds the initial
// state from the counter alone and a block costs no context writes; and CRD
// returns x[sel] + init[sel], folding ChaCha's feed-forward into the read so
// that no separate final instruction exists.
//
// No lane reads another, so the thread mask IS honoured.

module VX_sym_chacha import VX_gpu_pkg::*; #(
    parameter `STRING INSTANCE_ID = "",
    parameter NUM_LANES = 1
) (
    input wire              clk,
    input wire              reset,
    VX_execute_if.slave     execute_if,
    VX_result_if.master     result_if
);
    `UNUSED_SPARAM (INSTANCE_ID)
    localparam int NW = `VX_CFG_NUM_WARPS;

    function automatic logic [31:0] rol32 (input logic [31:0] x, input logic [4:0] n);
        return (n == 5'd0) ? x : ((x << n) | (x >> (6'd32 - {1'b0, n})));
    endfunction

    reg [NW-1:0][NUM_LANES-1:0][15:0][31:0] ctx_x;
    reg [NW-1:0][NUM_LANES-1:0][7:0][31:0]  ctx_k;
    reg [NW-1:0][NUM_LANES-1:0][2:0][31:0]  ctx_n;
    reg [NW-1:0][NUM_LANES-1:0][31:0]       ctx_ctr;

    wire [NW_WIDTH-1:0] cwid = execute_if.data.header.wid;
    wire [3:0] csel = execute_if.data.op_args.sym.shamt[3:0];

    wire is_cwr   = (execute_if.data.op_type == INST_OP_BITS'(INST_SYM_CHA_CWR));
    wire is_crd   = (execute_if.data.op_type == INST_OP_BITS'(INST_SYM_CHA_CRD));
    wire is_begin = (execute_if.data.op_type == INST_OP_BITS'(INST_SYM_CHA_BEGIN));
    wire is_dr    = (execute_if.data.op_type == INST_OP_BITS'(INST_SYM_CHA_DR));

    // Eight quarter-rounds, one per cycle: four column then four diagonal.
    reg [2:0] qr_step;
    wire last_step = (qr_step == 3'd7);

    // Which four state words this cycle's quarter-round touches. Columns first,
    // then diagonals; both are compile-time tables, not muxes on data.
    function automatic logic [3:0] qr_idx (input logic [2:0] st, input logic [1:0] which);
        logic [1:0] j;
        j = st[1:0];
        if (!st[2]) begin
            case (which)
                2'd0: return {2'b00, j};
                2'd1: return {2'b01, j};
                2'd2: return {2'b10, j};
                default: return {2'b11, j};
            endcase
        end else begin
            case (which)
                2'd0: return {2'b00, j};
                2'd1: return {2'b01, (j + 2'd1)};
                2'd2: return {2'b10, (j + 2'd2)};
                default: return {2'b11, (j + 2'd3)};
            endcase
        end
    endfunction

    wire [3:0] ia = qr_idx(qr_step, 2'd0);
    wire [3:0] ib = qr_idx(qr_step, 2'd1);
    wire [3:0] ic = qr_idx(qr_step, 2'd2);
    wire [3:0] id = qr_idx(qr_step, 2'd3);

    wire [NUM_LANES-1:0][31:0] qa, qb, qc, qd;
    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_qr
        wire [31:0] a0 = ctx_x[cwid][i][ia];
        wire [31:0] b0 = ctx_x[cwid][i][ib];
        wire [31:0] c0 = ctx_x[cwid][i][ic];
        wire [31:0] d0 = ctx_x[cwid][i][id];
        wire [31:0] a1 = a0 + b0;
        wire [31:0] d1 = rol32(d0 ^ a1, 5'd16);
        wire [31:0] c1 = c0 + d1;
        wire [31:0] b1 = rol32(b0 ^ c1, 5'd12);
        wire [31:0] a2 = a1 + b1;
        wire [31:0] d2 = rol32(d1 ^ a2, 5'd8);
        wire [31:0] c2 = c1 + d2;
        wire [31:0] b2 = rol32(b1 ^ c2, 5'd7);
        assign qa[i] = a2; assign qb[i] = b2;
        assign qc[i] = c2; assign qd[i] = d2;
    end

    // The initial state, rebuilt from the stored key, nonce and counter. Only
    // CRD reads it, and only to add it back.
    function automatic logic [31:0] sigma (input logic [1:0] j);
        case (j)
            2'd0: return 32'h61707865;
            2'd1: return 32'h3320646e;
            2'd2: return 32'h79622d32;
            default: return 32'h6b206574;
        endcase
    endfunction

    wire [NUM_LANES-1:0][31:0] init_w, crd_w;
    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_init
        assign init_w[i] = (csel < 4'd4)  ? sigma(csel[1:0])
                         : (csel < 4'd12) ? ctx_k[cwid][i][3'(csel - 4'd4)]
                         : (csel == 4'd12) ? ctx_ctr[cwid][i]
                                           : ctx_n[cwid][i][csel[1:0] - 2'd1];
        assign crd_w[i] = ctx_x[cwid][i][csel] + init_w[i];
    end

    wire cha_any = is_cwr | is_crd | is_begin | is_dr;
    wire eb_ready;
    wire fire = execute_if.valid && eb_ready;

    always @(posedge clk) begin
        if (reset) begin
            qr_step <= 3'd0;
        end else if (fire) begin
            if (is_dr) begin
                qr_step <= last_step ? 3'd0 : (qr_step + 3'd1);
                for (int i = 0; i < NUM_LANES; ++i) begin
                    if (execute_if.data.header.tmask[i]) begin
                        ctx_x[cwid][i][ia] <= qa[i];
                        ctx_x[cwid][i][ib] <= qb[i];
                        ctx_x[cwid][i][ic] <= qc[i];
                        ctx_x[cwid][i][id] <= qd[i];
                    end
                end
            end else if (is_begin) begin
                for (int i = 0; i < NUM_LANES; ++i) begin
                    if (execute_if.data.header.tmask[i]) begin
                        ctx_ctr[cwid][i] <= execute_if.data.rs1_data[i][31:0];
                        for (int j = 0; j < 4; ++j) begin
                            ctx_x[cwid][i][j] <= sigma(2'(j));
                        end
                        for (int j = 0; j < 8; ++j) begin
                            ctx_x[cwid][i][4 + j] <= ctx_k[cwid][i][j];
                        end
                        ctx_x[cwid][i][12] <= execute_if.data.rs1_data[i][31:0];
                        for (int j = 0; j < 3; ++j) begin
                            ctx_x[cwid][i][13 + j] <= ctx_n[cwid][i][j];
                        end
                    end
                end
            end else if (is_cwr) begin
                for (int i = 0; i < NUM_LANES; ++i) begin
                    if (execute_if.data.header.tmask[i]) begin
                        if (csel < 4'd8) begin
                            ctx_k[cwid][i][csel[2:0]] <= execute_if.data.rs1_data[i][31:0];
                        end else begin
                            ctx_n[cwid][i][csel[1:0]] <= execute_if.data.rs1_data[i][31:0];
                        end
                    end
                end
            end
        end
    end

    wire [NUM_LANES-1:0][`VX_CFG_XLEN-1:0] cha_result;
    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_out
        assign cha_result[i] = is_crd ? `VX_CFG_XLEN'(crd_w[i]) : '0;
    end

    wire unit_done = ~is_dr | last_step;
    assign execute_if.ready = eb_ready && unit_done;

    `UNUSED_VAR (execute_if.data.rs2_data)
    `UNUSED_VAR (execute_if.data.rs3_data)
    `UNUSED_VAR (cha_any)

    VX_elastic_buffer #(
        .DATAW ($bits(sym_header_t) + (NUM_LANES * `VX_CFG_XLEN))
    ) rsp_buf (
        .clk       (clk),
        .reset     (reset),
        .valid_in  (execute_if.valid && unit_done),
        .ready_in  (eb_ready),
        .data_in   ({execute_if.data.header, cha_result}),
        .data_out  ({result_if.data.header,  result_if.data.data}),
        .valid_out (result_if.valid),
        .ready_out (result_if.ready)
    );

endmodule
