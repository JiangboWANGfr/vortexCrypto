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

// Authentication-MAC execute unit. One PE today (GHASH); Poly1305 joins it
// later. See VX_sym_unit for why the VX_pe_switch stays at PE_COUNT == 1.

module VX_auth_unit import VX_gpu_pkg::*; #(
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

    localparam BLOCK_SIZE   = `VX_CFG_NUM_AUTH_BLOCKS;
    localparam NUM_LANES    = `VX_CFG_NUM_AUTH_LANES;
    localparam PARTIAL_BW   = (BLOCK_SIZE != `VX_CFG_ISSUE_WIDTH) || (NUM_LANES != `VX_CFG_SIMD_WIDTH);
`ifdef VX_CFG_EXT_AUTH_POLY_ENABLE
    localparam PE_COUNT     = 2;
`else
    localparam PE_COUNT     = 1;
`endif
    localparam PE_SEL_BITS  = `CLOG2(PE_COUNT);
    localparam PE_IDX_GHASH = 0;
    localparam PE_IDX_POLY  = 1;

    VX_execute_if #(
        .data_t (auth_execute_t)
    ) per_block_execute_if[BLOCK_SIZE]();

    VX_result_if #(
        .data_t (auth_result_t)
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
            .data_t (auth_execute_t)
        ) pe_execute_if[PE_COUNT]();

        VX_result_if #(
            .data_t (auth_result_t)
        ) pe_result_if[PE_COUNT]();

    `ifdef VX_CFG_EXT_AUTH_POLY_ENABLE
        // Poly1305's multiply-accumulate is ordinary integer arithmetic and
        // shares nothing with the carry-less field multiply next to it, so it
        // gets its own PE rather than another mode inside the GHASH datapath.
        wire is_poly = (per_block_execute_if[block_idx].data.op_type
                        == INST_OP_BITS'(INST_AUTH_POLY_MAC))
    `ifdef VX_CFG_EXT_AUTH_POLY_STEP16_ENABLE
                    || (per_block_execute_if[block_idx].data.op_type
                        == INST_OP_BITS'(INST_AUTH_POLY_STEP16))
    `endif
    `ifdef VX_CFG_EXT_AUTH_POLY_SG4_ENABLE
                    || (per_block_execute_if[block_idx].data.op_type
                        == INST_OP_BITS'(INST_AUTH_POLY_RSUM))
    `endif
                       ;
        wire [`UP(PE_SEL_BITS)-1:0] pe_select = is_poly ? PE_SEL_BITS'(PE_IDX_POLY)
                                                        : PE_SEL_BITS'(PE_IDX_GHASH);
    `else
        wire [`UP(PE_SEL_BITS)-1:0] pe_select = PE_IDX_GHASH;
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

        VX_auth_ghash #(
            .INSTANCE_ID (`SFORMATF(("%s-ghash%0d", INSTANCE_ID, block_idx))),
            .NUM_LANES   (NUM_LANES)
        ) auth_ghash (
            .clk        (clk),
            .reset      (reset),
            .execute_if (pe_execute_if[PE_IDX_GHASH]),
            .result_if  (pe_result_if[PE_IDX_GHASH])
        );

    `ifdef VX_CFG_EXT_AUTH_POLY_ENABLE
        VX_auth_poly #(
            .INSTANCE_ID (`SFORMATF(("%s-poly%0d", INSTANCE_ID, block_idx))),
            .NUM_LANES   (NUM_LANES)
        ) auth_poly (
            .clk        (clk),
            .reset      (reset),
            .execute_if (pe_execute_if[PE_IDX_POLY]),
            .result_if  (pe_result_if[PE_IDX_POLY])
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
