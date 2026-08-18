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

#ifndef __VX_AES_H__
#define __VX_AES_H__

#include <stdint.h>
#include <crypto/vx_crypto_defs.h>

// AES round transforms -- RISC-V Zkne, RV32 forms. Executed by EX_SYM
// (hw/rtl/crypto/sym/VX_sym_aes.sv, sim/simx/sym_unit.cpp).
//
// Each instruction consumes ONE byte of rs2, selected by `bs`, and XORs its
// transformed contribution into rs1. Four of them build one output column, so a
// full round is sixteen. `bs` is an instruction field, so it must be a
// compile-time constant -- hence macros rather than functions.
//
// State words are LITTLE-endian packed columns: row r of column c sits at bit
// 8r of word c, which is what `(rs2 >> 8*bs)` selects. A key schedule packed
// big-endian (the usual FIPS-197 word order) must be byte-swapped first.
//
// Only the encrypt direction is implemented. GCM runs AES in counter mode,
// which never decrypts; Zknd (aes32dsi/aes32dsmi) is absent by design, not by
// omission.

#ifdef __cplusplus
extern "C" {
#endif

// Final-round byte step, no MixColumns:
//   rd = rs1 ^ rol32(zext32(sbox(byte bs of rs2)), 8*bs)
// funct7 = {bs[1:0], funct5[4:0]}, funct5 = 0b10001.
#define vx_aes32esi(a, b, bs) ({                                             \
    uint32_t __out;                                                          \
    __asm__ (".insn r %1, 0, %4, %0, %2, %3"                                 \
             : "=r"(__out)                                                   \
             : "i"(RISCV_OP), "r"((uint32_t)(a)), "r"((uint32_t)(b)),        \
               "i"(0x11 | (((bs) & 3) << 5)));                               \
    __out;                                                                   \
})

// Middle-round byte step, with MixColumns:
//   rd = rs1 ^ rol32(mixcolumn(sbox(byte bs of rs2)), 8*bs)
// funct5 = 0b10011.
#define vx_aes32esmi(a, b, bs) ({                                            \
    uint32_t __out;                                                          \
    __asm__ (".insn r %1, 0, %4, %0, %2, %3"                                 \
             : "=r"(__out)                                                   \
             : "i"(RISCV_OP), "r"((uint32_t)(a)), "r"((uint32_t)(b)),        \
               "i"(0x13 | (((bs) & 3) << 5)));                               \
    __out;                                                                   \
})

#ifdef __cplusplus
}
#endif

#endif // __VX_AES_H__
