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

// AES processing element: the ratified RISC-V Zkne RV32 encrypt instructions.
//
//   AES32ESI  rd, rs1, rs2, bs   rd = rs1 ^ rol32(zext32(sbox(byte bs of rs2)), 8*bs)
//   AES32ESMI rd, rs1, rs2, bs   rd = rs1 ^ rol32(mixcol(sbox(byte bs of rs2)), 8*bs)
//
// Both are 2R1W: rd is written only, never read, so no third register port is
// needed. Fixed one cycle, combinational datapath plus a single elastic buffer,
// so execute_if.ready is never held low for more than one cycle -- this unit
// cannot head-of-line block anything behind it.
//
// GCM uses AES in counter mode, which only ever encrypts, so the decrypt
// direction (AES32DSI/AES32DSMI, Zknd) is deliberately not implemented.

module VX_sym_aes import VX_gpu_pkg::*; #(
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

    // AES32* is an RV32 encoding; RV64 uses the AES64* family, which this unit
    // does not implement. At XLEN=64 the datapath below would XOR a
    // zero-extended 32-bit result into a 64-bit rs1 and leave the upper half of
    // rd equal to the upper half of rs1, while simx would zero it -- two models
    // silently disagreeing.
    //
    // STATIC_ASSERT cannot express this: it expands to nothing under SYNTHESIS
    // (VX_platform.vh:136), and the DE10-Pro flow defines SYNTHESIS, so the
    // check would be absent from exactly the build that matters. A reference to
    // a module that does not exist fails elaboration in Verilator and in
    // Quartus alike, and names the reason where the tool prints it.
`ifdef VX_CFG_XLEN_64
    VX_sym_aes_requires_XLEN_32__use_AES64_for_RV64 __config_error();
`endif

    // AES forward S-box (FIPS-197 figure 7). The table is written in natural
    // order (input 0 first) but declared descending to match the house style,
    // so the concatenation puts input 0 at the TOP index and the lookup is
    // sbox[255 - x] rather than sbox[x].
    function automatic logic [7:0] aes_sbox_fwd (input logic [7:0] x);
        logic [255:0][7:0] sbox;
        sbox = {
            8'h63, 8'h7c, 8'h77, 8'h7b, 8'hf2, 8'h6b, 8'h6f, 8'hc5,
            8'h30, 8'h01, 8'h67, 8'h2b, 8'hfe, 8'hd7, 8'hab, 8'h76,
            8'hca, 8'h82, 8'hc9, 8'h7d, 8'hfa, 8'h59, 8'h47, 8'hf0,
            8'had, 8'hd4, 8'ha2, 8'haf, 8'h9c, 8'ha4, 8'h72, 8'hc0,
            8'hb7, 8'hfd, 8'h93, 8'h26, 8'h36, 8'h3f, 8'hf7, 8'hcc,
            8'h34, 8'ha5, 8'he5, 8'hf1, 8'h71, 8'hd8, 8'h31, 8'h15,
            8'h04, 8'hc7, 8'h23, 8'hc3, 8'h18, 8'h96, 8'h05, 8'h9a,
            8'h07, 8'h12, 8'h80, 8'he2, 8'heb, 8'h27, 8'hb2, 8'h75,
            8'h09, 8'h83, 8'h2c, 8'h1a, 8'h1b, 8'h6e, 8'h5a, 8'ha0,
            8'h52, 8'h3b, 8'hd6, 8'hb3, 8'h29, 8'he3, 8'h2f, 8'h84,
            8'h53, 8'hd1, 8'h00, 8'hed, 8'h20, 8'hfc, 8'hb1, 8'h5b,
            8'h6a, 8'hcb, 8'hbe, 8'h39, 8'h4a, 8'h4c, 8'h58, 8'hcf,
            8'hd0, 8'hef, 8'haa, 8'hfb, 8'h43, 8'h4d, 8'h33, 8'h85,
            8'h45, 8'hf9, 8'h02, 8'h7f, 8'h50, 8'h3c, 8'h9f, 8'ha8,
            8'h51, 8'ha3, 8'h40, 8'h8f, 8'h92, 8'h9d, 8'h38, 8'hf5,
            8'hbc, 8'hb6, 8'hda, 8'h21, 8'h10, 8'hff, 8'hf3, 8'hd2,
            8'hcd, 8'h0c, 8'h13, 8'hec, 8'h5f, 8'h97, 8'h44, 8'h17,
            8'hc4, 8'ha7, 8'h7e, 8'h3d, 8'h64, 8'h5d, 8'h19, 8'h73,
            8'h60, 8'h81, 8'h4f, 8'hdc, 8'h22, 8'h2a, 8'h90, 8'h88,
            8'h46, 8'hee, 8'hb8, 8'h14, 8'hde, 8'h5e, 8'h0b, 8'hdb,
            8'he0, 8'h32, 8'h3a, 8'h0a, 8'h49, 8'h06, 8'h24, 8'h5c,
            8'hc2, 8'hd3, 8'hac, 8'h62, 8'h91, 8'h95, 8'he4, 8'h79,
            8'he7, 8'hc8, 8'h37, 8'h6d, 8'h8d, 8'hd5, 8'h4e, 8'ha9,
            8'h6c, 8'h56, 8'hf4, 8'hea, 8'h65, 8'h7a, 8'hae, 8'h08,
            8'hba, 8'h78, 8'h25, 8'h2e, 8'h1c, 8'ha6, 8'hb4, 8'hc6,
            8'he8, 8'hdd, 8'h74, 8'h1f, 8'h4b, 8'hbd, 8'h8b, 8'h8a,
            8'h70, 8'h3e, 8'hb5, 8'h66, 8'h48, 8'h03, 8'hf6, 8'h0e,
            8'h61, 8'h35, 8'h57, 8'hb9, 8'h86, 8'hc1, 8'h1d, 8'h9e,
            8'he1, 8'hf8, 8'h98, 8'h11, 8'h69, 8'hd9, 8'h8e, 8'h94,
            8'h9b, 8'h1e, 8'h87, 8'he9, 8'hce, 8'h55, 8'h28, 8'hdf,
            8'h8c, 8'ha1, 8'h89, 8'h0d, 8'hbf, 8'he6, 8'h42, 8'h68,
            8'h41, 8'h99, 8'h2d, 8'h0f, 8'hb0, 8'h54, 8'hbb, 8'h16
        };
        return sbox[255 - x];
    endfunction

    // GF(2^8) multiply by 2 under the AES polynomial x^8+x^4+x^3+x+1 (0x11b).
    function automatic logic [7:0] aes_xtime2 (input logic [7:0] x);
        return {x[6:0], 1'b0} ^ (x[7] ? 8'h1b : 8'h00);
    endfunction

    // MixColumns contribution of a single byte: column [2s, s, s, 3s] packed
    // little-endian, so row 0 (2s) lands in the low byte.
    function automatic logic [31:0] aes_mixcol_byte (input logic [7:0] s);
        logic [7:0] s2 = aes_xtime2(s);
        return {s2 ^ s, s, s, s2};
    endfunction

    function automatic logic [31:0] rol32 (input logic [31:0] x, input logic [1:0] bs);
        case (bs)
            2'd0: return x;
            2'd1: return {x[23:0], x[31:24]};
            2'd2: return {x[15:0], x[31:16]};
            default: return {x[7:0], x[31:8]};
        endcase
    endfunction

    wire [1:0] bs = execute_if.data.op_args.sym.bs;
    wire is_mix = (execute_if.data.op_type == INST_SYM_AES32ESMI);

    wire [NUM_LANES-1:0][`VX_CFG_XLEN-1:0] aes_result;

    for (genvar i = 0; i < NUM_LANES; ++i) begin : g_lanes
        wire [7:0]  sel_byte = execute_if.data.rs2_data[i][8*bs +: 8];
        wire [7:0]  sbox_out = aes_sbox_fwd(sel_byte);
        wire [31:0] so       = is_mix ? aes_mixcol_byte(sbox_out) : {24'b0, sbox_out};
        assign aes_result[i] = execute_if.data.rs1_data[i] ^ rol32(so, bs);
    end

    `UNUSED_VAR (execute_if.data.rs3_data)

    VX_elastic_buffer #(
        .DATAW ($bits(sym_header_t) + (NUM_LANES * `VX_CFG_XLEN))
    ) rsp_buf (
        .clk       (clk),
        .reset     (reset),
        .valid_in  (execute_if.valid),
        .ready_in  (execute_if.ready),
        .data_in   ({execute_if.data.header,  aes_result}),
        .data_out  ({result_if.data.header,   result_if.data.data}),
        .valid_out (result_if.valid),
        .ready_out (result_if.ready)
    );

endmodule
