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

    // Context lifetime. The context arrays above are 57,344 bits; clearing them
    // on reset would put a reset net on every one of those flops, and the
    // Vortex domain closes with 0.183 ns to spare. These 704 bits carry the
    // same architectural guarantee at 1.2% of the flops: a word that has not
    // been written by this context reads as zero, so a kernel cannot recover
    // its predecessor's key by issuing cha.begin and cha.crd without first
    // writing a key of its own. The bits are physically still there; this is a
    // readability guarantee, not erasure, and section 24 says so.
    reg [NW-1:0][NUM_LANES-1:0][10:0]       ctx_written;  // 8 key words + 3 nonce
    reg [NW-1:0][NUM_LANES-1:0]             ctx_ready;    // cha.begin has run

    wire [NW_WIDTH-1:0] cwid = execute_if.data.header.wid;
    wire [3:0] csel = execute_if.data.op_args.sym.shamt[3:0];

    wire is_cwr   = (execute_if.data.op_type == INST_OP_BITS'(INST_SYM_CHA_CWR));
    wire is_crd   = (execute_if.data.op_type == INST_OP_BITS'(INST_SYM_CHA_CRD));
    wire is_begin = (execute_if.data.op_type == INST_OP_BITS'(INST_SYM_CHA_BEGIN));
    wire is_dr    = (execute_if.data.op_type == INST_OP_BITS'(INST_SYM_CHA_DR));

    // Eight quarter-rounds per double-round, and each quarter-round is itself
    // pipelined TWO deep. The first build did a whole quarter-round in one
    // cycle and the Vortex clock fell to 130.82 MHz, with all sixty of the
    // worst paths inside this module.
    //
    // A quarter-round is eight strictly dependent steps:
    //
    //   a += b;  d = rol(d^a,16);  c += d;  b = rol(b^c,12);
    //   a += b;  d = rol(d^a, 8);  c += d;  b = rol(b^c, 7);
    //
    // On top of four 16:1 reads of the state, because the operand indices come
    // from the step counter rather than a genvar. Splitting the lane loop was
    // not enough -- the same mistake the GHASH engine made, where the lanes were
    // walked but the multiply was left whole.
    //
    // Two stages of four steps each: throughput stays one quarter-round per
    // cycle, so a double-round costs 8 + 1 cycles instead of 8.
    // Ten steps, not eight: the pipe must drain at the column-to-diagonal seam
    // as well as at the end. Quarter-rounds 0..3 touch disjoint columns and
    // 4..7 disjoint diagonals, but the last column round writes x[15] and the
    // first diagonal round reads it, so issuing them back to back would read
    // the stale word. Steps 4 and 9 issue nothing.
    reg [3:0] qr_step;
    wire issue = (qr_step < 4'd4) || (qr_step > 4'd4 && qr_step < 4'd9);
    wire last_step = (qr_step == 4'd9);
    wire [2:0] qr_sel = (qr_step < 4'd4) ? qr_step[2:0]
                                         : (3'(qr_step - 4'd1) | 3'd4);

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

    wire [2:0] st0 = qr_sel;
    wire [3:0] ia = qr_idx(st0, 2'd0);
    wire [3:0] ib = qr_idx(st0, 2'd1);
    wire [3:0] ic = qr_idx(st0, 2'd2);
    wire [3:0] id = qr_idx(st0, 2'd3);

    // S0: the four state reads and the first half of the quarter-round.
    wire [NUM_LANES-1:0][31:0] h_a, h_b, h_c, h_d;
    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_qr0
        wire [31:0] a0 = ctx_x[cwid][i][ia];
        wire [31:0] b0 = ctx_x[cwid][i][ib];
        wire [31:0] c0 = ctx_x[cwid][i][ic];
        wire [31:0] d0 = ctx_x[cwid][i][id];
        wire [31:0] a1 = a0 + b0;
        wire [31:0] d1 = rol32(d0 ^ a1, 5'd16);
        wire [31:0] c1 = c0 + d1;
        wire [31:0] b1 = rol32(b0 ^ c1, 5'd12);
        assign h_a[i] = a1; assign h_b[i] = b1;
        assign h_c[i] = c1; assign h_d[i] = d1;
    end

    reg                        s1_valid;
    reg [3:0]                  s1_ia, s1_ib, s1_ic, s1_id;
    reg [NW_WIDTH-1:0]         s1_wid;
    reg [NUM_LANES-1:0]        s1_tmask;
    reg [NUM_LANES-1:0][31:0]  s1_a, s1_b, s1_c, s1_d;

    // S1: the second half, from the latch.
    wire [NUM_LANES-1:0][31:0] qa, qb, qc, qd;
    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_qr1
        wire [31:0] a2 = s1_a[i] + s1_b[i];
        wire [31:0] d2 = rol32(s1_d[i] ^ a2, 5'd8);
        wire [31:0] c2 = s1_c[i] + d2;
        wire [31:0] b2 = rol32(s1_b[i] ^ c2, 5'd7);
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
        wire k_ok = ctx_written[cwid][i][3'(csel - 4'd4)];
        wire n_ok = ctx_written[cwid][i][8 + (csel[1:0] - 2'd1)];
        assign init_w[i] = (csel < 4'd4)  ? sigma(csel[1:0])
                         : (csel < 4'd12) ? (k_ok ? ctx_k[cwid][i][3'(csel - 4'd4)] : 32'b0)
                         : (csel == 4'd12) ? ctx_ctr[cwid][i]
                                           : (n_ok ? ctx_n[cwid][i][csel[1:0] - 2'd1] : 32'b0);
        assign crd_w[i] = ctx_x[cwid][i][csel] + init_w[i];
    end

    wire cha_any = is_cwr | is_crd | is_begin | is_dr;

`ifdef SIMULATION
    // cha.dr and cha.crd operate on state that cha.begin builds. Issuing either
    // before it is a kernel bug, and a silent one: the words read are whatever
    // the previous owner of this (warp, lane) context left, and a ChaCha
    // keystream is uniformly random-looking whether it is the right one or not.
    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_ready_chk
        `RUNTIME_ASSERT(!(execute_if.valid && (is_dr || is_crd)
                          && execute_if.data.header.tmask[i])
                        || ctx_ready[cwid][i],
            ("cha.dr/crd on a context that cha.begin has not built: wid=%0d, lane=%0d",
                cwid, i))
    end
`endif
    wire eb_ready;
    wire fire = execute_if.valid && eb_ready;

    always @(posedge clk) begin
        if (reset) begin
            qr_step     <= 4'd0;
            s1_valid    <= 1'b0;
            ctx_written <= '0;
            ctx_ready   <= '0;
        end else if (fire) begin
            if (is_dr) begin
                qr_step <= last_step ? 4'd0 : (qr_step + 4'd1);
                // S0 -> S1
                s1_valid <= issue;
                s1_ia <= ia; s1_ib <= ib; s1_ic <= ic; s1_id <= id;
                s1_wid <= cwid;
                s1_tmask <= execute_if.data.header.tmask;
                s1_a <= h_a; s1_b <= h_b; s1_c <= h_c; s1_d <= h_d;
                // S1 -> context. The four words a quarter-round touches are
                // distinct, and consecutive quarter-rounds of a column round
                // touch disjoint columns, so the one-cycle gap between reading
                // and writing cannot alias inside a round. The diagonal round
                // follows the column round through the same pipe, and the extra
                // drain step separates them.
                if (s1_valid) begin
                    for (int i = 0; i < NUM_LANES; ++i) begin
                        if (s1_tmask[i]) begin
                            ctx_x[s1_wid][i][s1_ia] <= qa[i];
                            ctx_x[s1_wid][i][s1_ib] <= qb[i];
                            ctx_x[s1_wid][i][s1_ic] <= qc[i];
                            ctx_x[s1_wid][i][s1_id] <= qd[i];
                        end
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
                            ctx_x[cwid][i][4 + j] <= ctx_written[cwid][i][j]
                                                   ? ctx_k[cwid][i][j] : 32'b0;
                        end
                        ctx_x[cwid][i][12] <= execute_if.data.rs1_data[i][31:0];
                        for (int j = 0; j < 3; ++j) begin
                            ctx_x[cwid][i][13 + j] <= ctx_written[cwid][i][8 + j]
                                                    ? ctx_n[cwid][i][j] : 32'b0;
                        end
                        ctx_ready[cwid][i] <= 1'b1;
                    end
                end
            end else if (is_cwr) begin
                for (int i = 0; i < NUM_LANES; ++i) begin
                    if (execute_if.data.header.tmask[i]) begin
                        if (csel < 4'd8) begin
                            ctx_k[cwid][i][csel[2:0]] <= execute_if.data.rs1_data[i][31:0];
                            ctx_written[cwid][i][csel[2:0]] <= 1'b1;
                        end else begin
                            ctx_n[cwid][i][csel[1:0]] <= execute_if.data.rs1_data[i][31:0];
                            ctx_written[cwid][i][8 + csel[1:0]] <= 1'b1;
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
