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

// Symmetric-cipher execute unit. Two PEs: the AES round transforms, and the
// rotate that ChaCha20 is built from. They are separate PEs rather than one
// because they share no logic -- an S-box and a barrel shifter -- and because
// VX_sym_rot is not a cryptographic transform at all (see its header).

module VX_sym_unit import VX_gpu_pkg::*; #(
    parameter `STRING INSTANCE_ID = ""
) (
    input wire              clk,
    input wire              reset,

    // Inputs
    VX_dispatch_if.slave    dispatch_if [`VX_CFG_ISSUE_WIDTH],

    // Outputs
    VX_commit_if.master     commit_if [`VX_CFG_ISSUE_WIDTH]
);
    `UNUSED_SPARAM (INSTANCE_ID)

    localparam BLOCK_SIZE  = `VX_CFG_NUM_SYM_BLOCKS;
    localparam NUM_LANES   = `VX_CFG_NUM_SYM_LANES;
    localparam PARTIAL_BW  = (BLOCK_SIZE != `VX_CFG_ISSUE_WIDTH) || (NUM_LANES != `VX_CFG_SIMD_WIDTH);
`ifdef VX_CFG_EXT_SYM_CHACHA_S2_ENABLE
    localparam PE_COUNT    = 3;
`else
    localparam PE_COUNT    = 2;
`endif
    localparam PE_SEL_BITS = `CLOG2(PE_COUNT);
    localparam PE_IDX_AES  = 0;
    localparam PE_IDX_ROT  = 1;
    localparam PE_IDX_CHA  = 2;

    VX_execute_if #(
        .data_t (sym_execute_t)
    ) per_block_execute_if[BLOCK_SIZE]();

    VX_result_if #(
        .data_t (sym_result_t)
    ) per_block_result_if[BLOCK_SIZE]();

    VX_lane_dispatch #(
        .BLOCK_SIZE (BLOCK_SIZE),
        .NUM_LANES  (NUM_LANES),
        .OUT_BUF    (PARTIAL_BW ? 3 : 0)
    ) lane_dispatch (
        .clk        (clk),
        .reset      (reset),
        .dispatch_if(dispatch_if),
        .execute_if (per_block_execute_if)
    );

    for (genvar block_idx = 0; block_idx < BLOCK_SIZE; ++block_idx) begin : g_blocks

        VX_execute_if #(
            .data_t (sym_execute_t)
        ) pe_execute_if[PE_COUNT]();

        VX_result_if #(
            .data_t (sym_result_t)
        ) pe_result_if[PE_COUNT]();

        // Both rotate-family ops go to the rotate PE: RORI, and -- when built --
        // ChaCha's fused xor-then-rotate, which is the same shifter with an XOR
        // in front of it.
        wire is_rot = (per_block_execute_if[block_idx].data.op_type == INST_OP_BITS'(INST_SYM_RORI))
    `ifdef VX_CFG_EXT_SYM_CHACHA_ENABLE
                   || (per_block_execute_if[block_idx].data.op_type == INST_OP_BITS'(INST_SYM_CHACHA_XR))
    `endif
    `ifdef VX_CFG_EXT_SYM_CHACHA_SG4_ENABLE
                   || (per_block_execute_if[block_idx].data.op_type == INST_OP_BITS'(INST_SYM_CHADD_SG4))
    `endif
                   ;
    `ifdef VX_CFG_EXT_SYM_CHACHA_S2_ENABLE
        // The stateful ChaCha engine keeps a whole 512-bit state per lane and
        // shares nothing with either of the others, so it gets its own PE.
        wire is_cha = (per_block_execute_if[block_idx].data.op_type == INST_OP_BITS'(INST_SYM_CHA_CWR))
                   || (per_block_execute_if[block_idx].data.op_type == INST_OP_BITS'(INST_SYM_CHA_CRD))
                   || (per_block_execute_if[block_idx].data.op_type == INST_OP_BITS'(INST_SYM_CHA_BEGIN))
                   || (per_block_execute_if[block_idx].data.op_type == INST_OP_BITS'(INST_SYM_CHA_DR));
        wire [`UP(PE_SEL_BITS)-1:0] pe_select = is_cha ? PE_SEL_BITS'(PE_IDX_CHA)
                                              : (is_rot ? PE_SEL_BITS'(PE_IDX_ROT)
                                                        : PE_SEL_BITS'(PE_IDX_AES));
    `else
        wire [`UP(PE_SEL_BITS)-1:0] pe_select = is_rot ? PE_IDX_ROT : PE_IDX_AES;
    `endif

        VX_pe_switch #(
            .PE_COUNT    (PE_COUNT),
            .NUM_LANES   (NUM_LANES),
            .ARBITER     ("R"),
            .REQ_OUT_BUF (0),
            .RSP_OUT_BUF (PARTIAL_BW ? 1 : 3)
        ) pe_switch (
            .clk            (clk),
            .reset          (reset),
            .pe_sel         (pe_select),
            .execute_in_if  (per_block_execute_if[block_idx]),
            .result_out_if  (per_block_result_if[block_idx]),
            .execute_out_if (pe_execute_if),
            .result_in_if   (pe_result_if)
        );

        VX_sym_aes #(
            .INSTANCE_ID (`SFORMATF(("%s-aes%0d", INSTANCE_ID, block_idx))),
            .NUM_LANES   (NUM_LANES)
        ) sym_aes (
            .clk        (clk),
            .reset      (reset),
            .execute_if (pe_execute_if[PE_IDX_AES]),
            .result_if  (pe_result_if[PE_IDX_AES])
        );

        VX_sym_rot #(
            .INSTANCE_ID (`SFORMATF(("%s-rot%0d", INSTANCE_ID, block_idx))),
            .NUM_LANES   (NUM_LANES)
        ) sym_rot (
            .clk        (clk),
            .reset      (reset),
            .execute_if (pe_execute_if[PE_IDX_ROT]),
            .result_if  (pe_result_if[PE_IDX_ROT])
        );

    `ifdef VX_CFG_EXT_SYM_CHACHA_S2_ENABLE
        VX_sym_chacha #(
            .INSTANCE_ID (`SFORMATF(("%s-cha%0d", INSTANCE_ID, block_idx))),
            .NUM_LANES   (NUM_LANES)
        ) sym_chacha (
            .clk        (clk),
            .reset      (reset),
            .execute_if (pe_execute_if[PE_IDX_CHA]),
            .result_if  (pe_result_if[PE_IDX_CHA])
        );
    `endif
    end

    VX_lane_gather #(
        .BLOCK_SIZE (BLOCK_SIZE),
        .NUM_LANES  (NUM_LANES),
        .OUT_BUF    (PARTIAL_BW ? 3 : 0)
    ) lane_gather (
        .clk       (clk),
        .reset     (reset),
        .result_if (per_block_result_if),
        .commit_if (commit_if)
    );

endmodule
