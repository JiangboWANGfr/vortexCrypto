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

// GHASH processing element: the ratified carry-less multiply (Zbkc) and the
// byte-wise bit reversal (Zbkb) that a GF(2^128) GHASH is built from.
//
//   CLMUL  rd, rs1, rs2   rd = low  XLEN bits of the carry-less product
//   CLMULH rd, rs1, rs2   rd = high XLEN bits of the carry-less product
//   BREV8  rd, rs1        rd = rs1 with the bits of each byte reversed
//   GHRED32L/H rd,rs1,rs2 rd = rs1 ^ clmul_{lo,hi}(rs2, 0x87)   [custom]
//
// GHRED32L/H are the only non-ratified instructions here. They fuse the
// multiply-by-the-reduction-constant with its accumulate, which is the shape
// the GF(2^128) fold takes: 0x87 is a compile-time constant, so the multiply
// collapses to four shifted XORs instead of a general carry-less multiply.
//
// BREV8 is here rather than in the integer ALU because it exists in this design
// for GHASH: GCM numbers the bits of each byte in the opposite order to the
// polynomial convention CLMUL assumes, so every operand entering the multiply
// is reflected first. Keeping it in the same unit keeps the whole GHASH inner
// loop inside one scheduling domain.
//
// All three are single-cycle, stateless and lane-local. No accumulator lives
// here: the running Y and the hash subkey H stay in the register file, which is
// what makes this unit context-switch safe and free of hidden state.

module VX_auth_ghash import VX_gpu_pkg::*; #(
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

    wire is_clmulh = (execute_if.data.op_type == INST_AUTH_CLMULH);
    wire is_brev8  = (execute_if.data.op_type == INST_AUTH_BREV8);
    wire is_ghred_l = (execute_if.data.op_type == INST_AUTH_GHRED32L);
    wire is_ghred_h = (execute_if.data.op_type == INST_AUTH_GHRED32H);

    wire [NUM_LANES-1:0][XLEN-1:0] auth_result;

    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_lanes
        wire [XLEN-1:0] a = execute_if.data.rs1_data[i];
        wire [XLEN-1:0] b = execute_if.data.rs2_data[i];

        // Carry-less product: XOR of shifted copies of a, selected by bits of b.
        // Written as a reduction tree so synthesis flattens it rather than
        // inferring a carry chain.
        logic [2*XLEN-1:0] clmul_prod;
        always @(*) begin
            clmul_prod = '0;
            for (int k = 0; k < XLEN; ++k) begin
                if (b[k]) begin
                    clmul_prod ^= ({{XLEN{1'b0}}, a} << k);
                end
            end
        end

        // Bit reversal within each byte.
        wire [XLEN-1:0] brev8_res;
        for (genvar j = 0; j < XLEN / 8; ++j) begin : g_brev8_bytes
            for (genvar k = 0; k < 8; ++k) begin : g_brev8_bits
                assign brev8_res[8*j + k] = a[8*j + (7 - k)];
            end
        end

        // Fused reduction: the GF(2^128) modulus x^128+x^7+x^2+x+1 reduces to
        // the constant 0x87 = 0b10000111, so multiplying by it carry-lessly is
        // just x ^ (x<<1) ^ (x<<2) ^ (x<<7). With a constant operand this is
        // four shifted XORs rather than the full 32-term reduction tree the
        // generic clmul needs, and the accumulate is folded in for free.
        wire [2*XLEN-1:0] b_ext = {{XLEN{1'b0}}, b};
        wire [2*XLEN-1:0] ghred_prod = b_ext ^ (b_ext << 1) ^ (b_ext << 2) ^ (b_ext << 7);
        wire [XLEN-1:0] ghred_lo = a ^ ghred_prod[XLEN-1:0];
        wire [XLEN-1:0] ghred_hi = a ^ ghred_prod[2*XLEN-1:XLEN];

        assign auth_result[i] = is_brev8    ? brev8_res
                              : is_ghred_l  ? ghred_lo
                              : is_ghred_h  ? ghred_hi
                              : is_clmulh   ? clmul_prod[2*XLEN-1:XLEN]
                                            : clmul_prod[XLEN-1:0];
    end

// GF(2^128) primitives in the reflected limb domain. Declared outside both
// feature guards because ghmul.sg4 and the stateful per-lane engine use the
// same arithmetic, and a second copy would drift. A function with no caller
// elaborates to nothing.
    function automatic logic [2*XLEN-1:0] clmul64 (input logic [XLEN-1:0] a,
                                                   input logic [XLEN-1:0] b);
        logic [2*XLEN-1:0] acc;
        acc = '0;
        for (int k = 0; k < XLEN; ++k) begin
            if (b[k]) begin
                acc ^= ({{XLEN{1'b0}}, a} << k);
            end
        end
        return acc;
    endfunction

    // Multiply by the constant 0x87, the reduction of x^128. Four shifted XORs
    // rather than a full multiplier, exactly as the ghred32 path does it.
    function automatic logic [2*XLEN-1:0] mul87 (input logic [XLEN-1:0] x);
        logic [2*XLEN-1:0] e;
        e = {{XLEN{1'b0}}, x};
        return e ^ (e << 1) ^ (e << 2) ^ (e << 7);
    endfunction


`ifdef VX_CFG_EXT_AUTH_SG4_ENABLE
    // Stateless subgroup GF(2^128) multiply.
    //
    //   ghmul.sg4 rd, rs1, rs2   with A = sum A_i x^(32i) over the quad's rs1
    //                            and H likewise over rs2, lane i receives limb i
    //                            of A*H mod x^128+x^7+x^2+x+1.
    //
    // Same reflected limb domain and the same reduction as the software
    // ghash_mul_hw it replaces, so the kernel's brev8 conventions are unchanged.
    //
    // COST, stated plainly: the schoolbook product is sixteen 32x32 carry-less
    // multiplies per quad, which is FOUR per lane against the one the lane-local
    // path needs. This is the largest crypto block in the design and this
    // quadruples its multiplier array.
    //
    // PRECONDITION: the quad must be converged. Every lane's operands are read
    // by the whole quad and the source lane's mask is not consulted, matching
    // aesrm.sg4 and, deliberately, not matching SHFL.
    if ((NUM_LANES < 4) || ((NUM_LANES % 4) != 0)) begin : g_sg4_guard
        VX_auth_ghash_sg4_requires_NUM_LANES_multiple_of_4 __config_error();
    end

    wire is_ghmul = (execute_if.data.op_type == INST_AUTH_GHMUL_SG4);
    wire [NUM_LANES-1:0][XLEN-1:0] ghmul_result;

    for (genvar q = 0; q < NUM_LANES / 4; ++q) begin : g_quads
        logic [7:0][XLEN-1:0] pp;
        logic [2*XLEN-1:0] prod;
        always @(*) begin
            // '0 rather than an assignment pattern: pp is PACKED, and '{default:'0}
            // is an unpacked-array form whose meaning here is not what it reads as.
            pp = '0;
            prod = '0;
            for (int i = 0; i < 4; ++i) begin
                for (int j = 0; j < 4; ++j) begin
                    prod = clmul64(execute_if.data.rs1_data[4*q+i],
                                   execute_if.data.rs2_data[4*q+j]);
                    pp[i+j]   = pp[i+j]   ^ prod[XLEN-1:0];
                    pp[i+j+1] = pp[i+j+1] ^ prod[2*XLEN-1:XLEN];
                end
            end
        end

        wire [2*XLEN-1:0] m4 = mul87(pp[4]);
        wire [2*XLEN-1:0] m5 = mul87(pp[5]);
        wire [2*XLEN-1:0] m6 = mul87(pp[6]);
        wire [2*XLEN-1:0] m7 = mul87(pp[7]);
        wire [2*XLEN-1:0] mc = mul87(m7[2*XLEN-1:XLEN]);

        assign ghmul_result[4*q+0] = pp[0] ^ m4[XLEN-1:0] ^ mc[XLEN-1:0];
        assign ghmul_result[4*q+1] = pp[1] ^ m4[2*XLEN-1:XLEN] ^ m5[XLEN-1:0];
        assign ghmul_result[4*q+2] = pp[2] ^ m5[2*XLEN-1:XLEN] ^ m6[XLEN-1:0];
        assign ghmul_result[4*q+3] = pp[3] ^ m6[2*XLEN-1:XLEN] ^ m7[XLEN-1:0];
    end

    wire [NUM_LANES-1:0][XLEN-1:0] unit_result;
    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_sel
        assign unit_result[i] = is_ghmul ? ghmul_result[i] : auth_result[i];
    end
`else
    wire [NUM_LANES-1:0][XLEN-1:0] unit_result = auth_result;
`endif

`ifdef VX_CFG_EXT_AUTH_S2_ENABLE
    // ------------------------------------------------------------------
    // Stateful per-lane GHASH engine (section 22 of the crypto proposal).
    //
    // Each lane owns H, Y and X keyed by (warp, lane), and one ghash.block
    // performs the whole update Y <- (Y ^ X)*H for every lane. The XOR that the
    // software path writes as `y[i] ^= v` is inside the instruction, so the
    // accumulator never leaves the context.
    //
    // ONE 128x128 multiplier is instantiated and shared: the engine walks one
    // lane per cycle, so ghash.block occupies the unit for NUM_LANES cycles.
    // That is the whole point -- a single-cycle form would need one multiplier
    // per lane, which at t16 across two cores is four times the ghmul.sg4 array
    // that already measured +46,423 ALMs on the DE10-Pro.
    //
    // Masked lanes still consume their cycle. Skipping them would make the
    // instruction's latency depend on the thread mask, and a cipher unit whose
    // timing varies with control flow is a side channel for no gain.
    localparam int NW = `VX_CFG_NUM_WARPS;
    localparam int LANE_W = (NUM_LANES > 1) ? $clog2(NUM_LANES) : 1;

    // No X register. ghash.cwr folds its limb straight into the accumulator, so
    // the sequence four-writes-then-block still computes Y <- (Y ^ X)*H while
    // storing 128 bits fewer per (warp, lane) -- 8,192 per core. It also takes
    // one array out of the S0 read mux and the XOR out of that stage.
    reg [NW-1:0][NUM_LANES-1:0][3:0][XLEN-1:0] gctx_h;
    reg [NW-1:0][NUM_LANES-1:0][3:0][XLEN-1:0] gctx_y;

    // Context lifetime; see VX_sym_chacha. ghash.init already clears Y, but H
    // is the subkey derived from the cipher key and nothing cleared it: a
    // successor issuing ghash.block would authenticate under its predecessor's
    // H. A word this context has not written reads as zero.
    reg [NW-1:0][NUM_LANES-1:0][3:0]           gctx_h_written;
    reg [NW-1:0][NUM_LANES-1:0]                gctx_ready;  // ghash.init has run

    wire [NW_WIDTH-1:0] g2_wid = execute_if.data.header.wid;
    wire [2:0] g2_sel = execute_if.data.op_args.sym.shamt[2:0];

    wire g2_cwr   = (execute_if.data.op_type == INST_AUTH_GH_CWR);
    wire g2_crd   = (execute_if.data.op_type == INST_AUTH_GH_CRD);
    wire g2_init  = (execute_if.data.op_type == INST_AUTH_GH_INIT);
    wire g2_block = (execute_if.data.op_type == INST_AUTH_GH_BLOCK);
    wire g2_any   = g2_cwr | g2_crd | g2_init | g2_block;

    // The multiply is pipelined THREE deep, not just walked lane by lane. The
    // first build put the whole chain -- a 64-entry context read mux, the XOR,
    // sixteen clmul32, the partial-product accumulate, the mul87 fold and the
    // context writeback -- in one cycle, and the Vortex clock fell from 208 MHz
    // to 131 with every one of the two hundred worst paths inside this module.
    //
    // The AES engine next door reads the same kind of context and does not
    // appear in that list, because each of its lanes reads its OWN entry: the
    // lane index is a genvar, so only the warp is muxed. This engine walks the
    // lanes with a counter, so its read is a 64:1 mux, and it then hangs a whole
    // GF(2^128) multiply off the end of it.
    //
    //   S0  context read mux, a = Y ^ X, b = H
    //   S1  sixteen clmul32 and the partial-product accumulate
    //   S2  mul87 fold and the writeback into Y
    //
    // Throughput stays one lane per cycle, so ghash.block costs NUM_LANES + 2
    // cycles instead of NUM_LANES -- two extra out of the ~441 a block-step
    // takes. Lanes are independent, so there is no hazard between the stages.
    localparam int STEP_W = $clog2(NUM_LANES + 2) + 1;
    reg [STEP_W-1:0] g2_step;
    wire [LANE_W-1:0] g2_rd_lane = g2_step[LANE_W-1:0];
    wire g2_rd_active = g2_block && (g2_step < STEP_W'(NUM_LANES));
    wire g2_done_step = (g2_step == STEP_W'(NUM_LANES + 1));

    // S0: the read mux, alone in its stage.
    wire [3:0][XLEN-1:0] g2_a, g2_b;
    for (genvar c = 0; c < 4; ++c) begin : g_g2_operand
        assign g2_a[c] = gctx_y[g2_wid][g2_rd_lane][c];
        assign g2_b[c] = gctx_h_written[g2_wid][g2_rd_lane][c]
                       ? gctx_h[g2_wid][g2_rd_lane][c] : XLEN'(0);
    end

    reg                  g2_s1_valid;
    reg [LANE_W-1:0]     g2_s1_lane;
    reg [NW_WIDTH-1:0]   g2_s1_wid;
    reg [3:0][XLEN-1:0]  g2_s1_a, g2_s1_b;

    // S1: the multiply array, fed from the S0 latch.
    logic [7:0][XLEN-1:0] g2_pp;
    always @(*) begin
        logic [2*XLEN-1:0] prod;
        g2_pp = '0;
        prod = '0;
        for (int i = 0; i < 4; ++i) begin
            for (int j = 0; j < 4; ++j) begin
                prod = clmul64(g2_s1_a[i], g2_s1_b[j]);
                g2_pp[i+j]   = g2_pp[i+j]   ^ prod[XLEN-1:0];
                g2_pp[i+j+1] = g2_pp[i+j+1] ^ prod[2*XLEN-1:XLEN];
            end
        end
    end

    reg                  g2_s2_valid;
    reg [LANE_W-1:0]     g2_s2_lane;
    reg [NW_WIDTH-1:0]   g2_s2_wid;
    reg [7:0][XLEN-1:0]  g2_s2_pp;

    // S2: the fold, from the S1 latch.
    wire [2*XLEN-1:0] g2_m4 = mul87(g2_s2_pp[4]);
    wire [2*XLEN-1:0] g2_m5 = mul87(g2_s2_pp[5]);
    wire [2*XLEN-1:0] g2_m6 = mul87(g2_s2_pp[6]);
    wire [2*XLEN-1:0] g2_m7 = mul87(g2_s2_pp[7]);
    wire [2*XLEN-1:0] g2_mc = mul87(g2_m7[2*XLEN-1:XLEN]);

    // The carry-out of the last fold is absorbed by the reduction, so only the
    // low limb of mc is meaningful; the same is true of the ghmul.sg4 path.
    `UNUSED_VAR (g2_mc)

    wire [3:0][XLEN-1:0] g2_r;
    assign g2_r[0] = g2_s2_pp[0] ^ g2_m4[XLEN-1:0] ^ g2_mc[XLEN-1:0];
    assign g2_r[1] = g2_s2_pp[1] ^ g2_m4[2*XLEN-1:XLEN] ^ g2_m5[XLEN-1:0];
    assign g2_r[2] = g2_s2_pp[2] ^ g2_m5[2*XLEN-1:XLEN] ^ g2_m6[XLEN-1:0];
    assign g2_r[3] = g2_s2_pp[3] ^ g2_m6[2*XLEN-1:XLEN] ^ g2_m7[XLEN-1:0];

    wire g2_fire = execute_if.valid && geb_ready;

    always @(posedge clk) begin
        if (reset) begin
            g2_step        <= '0;
            g2_s1_valid    <= 1'b0;
            g2_s2_valid    <= 1'b0;
            gctx_h_written <= '0;
            gctx_ready     <= '0;
        end else if (g2_fire) begin
            if (g2_block) begin
                g2_step <= g2_done_step ? '0 : (g2_step + STEP_W'(1));

                // S0 -> S1. Masked lanes still walk: skipping them would make
                // the instruction's latency depend on the thread mask, which is
                // a side channel for no gain.
                g2_s1_valid <= g2_rd_active && execute_if.data.header.tmask[g2_rd_lane];
                g2_s1_lane  <= g2_rd_lane;
                g2_s1_wid   <= g2_wid;
                g2_s1_a     <= g2_a;
                g2_s1_b     <= g2_b;

                // S1 -> S2
                g2_s2_valid <= g2_s1_valid;
                g2_s2_lane  <= g2_s1_lane;
                g2_s2_wid   <= g2_s1_wid;
                g2_s2_pp    <= g2_pp;

                // S2 -> context
                if (g2_s2_valid) begin
                    for (int c = 0; c < 4; ++c) begin
                        gctx_y[g2_s2_wid][g2_s2_lane][c] <= g2_r[c];
                    end
                end
            end else if (g2_init) begin
                for (int i = 0; i < NUM_LANES; ++i) begin
                    if (execute_if.data.header.tmask[i]) begin
                        for (int c = 0; c < 4; ++c) begin
                            gctx_y[g2_wid][i][c] <= '0;
                        end
                        gctx_ready[g2_wid][i] <= 1'b1;
                    end
                end
            end else if (g2_cwr) begin
                for (int i = 0; i < NUM_LANES; ++i) begin
                    if (execute_if.data.header.tmask[i]) begin
                        if (g2_sel[2] == 1'b0) begin
                            gctx_y[g2_wid][i][g2_sel[1:0]] <= gctx_y[g2_wid][i][g2_sel[1:0]]
                                                            ^ execute_if.data.rs1_data[i];
                        end else begin
                            gctx_h[g2_wid][i][g2_sel[1:0]] <= execute_if.data.rs1_data[i];
                            gctx_h_written[g2_wid][i][g2_sel[1:0]] <= 1'b1;
                        end
                    end
                end
            end
        end
    end

    wire [NUM_LANES-1:0][XLEN-1:0] g2_out;
    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_g2_rd
        assign g2_out[i] = g2_crd ? gctx_y[g2_wid][i][g2_sel[1:0]]
                         : (g2_any ? '0 : unit_result[i]);
    end

`ifdef SIMULATION
    // ghash.block and ghash.crd operate on an accumulator that ghash.init
    // clears. Without it the accumulator carries the previous owner's Y, and a
    // GCM tag is uniformly random-looking whether it is right or wrong.
    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_ready_chk
        `RUNTIME_ASSERT(!(execute_if.valid && (g2_block || g2_crd)
                          && execute_if.data.header.tmask[i])
                        || gctx_ready[g2_wid][i],
            ("ghash.block/crd on a context that ghash.init has not cleared: wid=%0d, lane=%0d",
                g2_wid, i))
    end
`endif

    wire unit_done = ~g2_block | g2_done_step;
`else
    wire [NUM_LANES-1:0][XLEN-1:0] g2_out = unit_result;
    wire unit_done = 1'b1;
`endif

    `UNUSED_VAR (execute_if.data.rs3_data)

    wire geb_ready;
    assign execute_if.ready = geb_ready && unit_done;

    VX_elastic_buffer #(
        .DATAW ($bits(auth_header_t) + (NUM_LANES * XLEN))
    ) rsp_buf (
        .clk       (clk),
        .reset     (reset),
        .valid_in  (execute_if.valid && unit_done),
        .ready_in  (geb_ready),
        .data_in   ({execute_if.data.header, g2_out}),
        .data_out  ({result_if.data.header,  result_if.data.data}),
        .valid_out (result_if.valid),
        .ready_out (result_if.ready)
    );

endmodule
