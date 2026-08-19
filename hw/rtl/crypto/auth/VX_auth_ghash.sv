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

    `UNUSED_VAR (execute_if.data.rs3_data)

    VX_elastic_buffer #(
        .DATAW ($bits(auth_header_t) + (NUM_LANES * XLEN))
    ) rsp_buf (
        .clk       (clk),
        .reset     (reset),
        .valid_in  (execute_if.valid),
        .ready_in  (execute_if.ready),
        .data_in   ({execute_if.data.header, unit_result}),
        .data_out  ({result_if.data.header,  result_if.data.data}),
        .valid_out (result_if.valid),
        .ready_out (result_if.ready)
    );

endmodule
