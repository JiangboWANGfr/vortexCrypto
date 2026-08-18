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

#ifndef __VX_CRYPTO_H__
#define __VX_CRYPTO_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Cryptographic instructions: EX_SYM (VX_sym_aes) and EX_AUTH (VX_auth_ghash).
//
// The ratified RISC-V encodings (Zbkc CLMUL/CLMULH, Zbkb BREV8, Zkne
// AES32ESI/AES32ESMI), reached through `.insn` rather than by naming the
// extension in -march. That is deliberate: naming e.g. _zbkb in -march lets
// clang emit ANY instruction of that extension anywhere in the program, and
// this design implements only the five below. Unimplemented encodings do NOT
// trap here -- they decode as some other instruction, and differently in RTL
// than in simx -- so an -march opt-in would be a silent-wrong-answer hazard.
// Explicit asm keeps emission under our control at zero cost to correctness.

#define RISCV_OP        0x33
#define RISCV_OP_IMM    0x13

// rd = low XLEN bits of the carry-less product of rs1 and rs2
__attribute__((always_inline))
inline uint32_t vx_clmul(uint32_t a, uint32_t b) {
    uint32_t out;
    __asm__ (".insn r %1, 1, 5, %0, %2, %3" : "=r"(out) : "i"(RISCV_OP), "r"(a), "r"(b));
    return out;
}

// rd = high XLEN bits of the carry-less product of rs1 and rs2
__attribute__((always_inline))
inline uint32_t vx_clmulh(uint32_t a, uint32_t b) {
    uint32_t out;
    __asm__ (".insn r %1, 3, 5, %0, %2, %3" : "=r"(out) : "i"(RISCV_OP), "r"(a), "r"(b));
    return out;
}

// rd = rs1 with the bits of each byte reversed
__attribute__((always_inline))
inline uint32_t vx_brev8(uint32_t a) {
    uint32_t out;
    __asm__ (".insn i %1, 5, %0, %2, 0x687" : "=r"(out) : "i"(RISCV_OP_IMM), "r"(a));
    return out;
}

// AES final-round byte step: rd = rs1 ^ rol32(sbox(byte bs of rs2), 8*bs).
// funct7 = {bs[1:0], funct5[4:0]}, funct5 = 0b10001. `bs` must be a constant.
#define vx_aes32esi(a, b, bs) ({                                             \
    uint32_t __out;                                                          \
    __asm__ (".insn r %1, 0, %4, %0, %2, %3"                                 \
             : "=r"(__out)                                                   \
             : "i"(RISCV_OP), "r"((uint32_t)(a)), "r"((uint32_t)(b)),        \
               "i"(0x11 | (((bs) & 3) << 5)));                               \
    __out;                                                                   \
})

// AES middle-round byte step, with MixColumns. funct5 = 0b10011.
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

#endif // __VX_CRYPTO_H__
