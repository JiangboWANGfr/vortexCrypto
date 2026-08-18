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

#ifndef __VX_GHASH_H__
#define __VX_GHASH_H__

#include <stdint.h>
#include <crypto/vx_crypto_defs.h>

// The GF(2^128) toolkit GHASH is built from -- RISC-V Zbkc (clmul, clmulh) and
// Zbkb (brev8). Executed by EX_AUTH (hw/rtl/crypto/auth/VX_auth_ghash.sv,
// sim/simx/auth_unit.cpp).
//
// These are general-purpose ratified instructions, not GHASH-specific: a
// carry-less multiply also serves CRC and polynomial arithmetic, and brev8 is
// plain bit manipulation. They are grouped here because GHASH is what motivated
// implementing them, and this is where a reader looking for the GHASH
// primitives will look. If another algorithm comes to depend on them, this
// header is the thing to share, not to copy.
//
// Bit order, which is the part that is easy to get silently wrong: GCM numbers
// the bits of each byte in the opposite order to the polynomial convention
// clmul assumes -- the coefficient of x^i is bit (7 - i%8) of byte i/8. A
// little-endian word load puts that at bit 8*(i/8) + 7 - i%8, so brev8 alone
// moves it to bit i and limb order is already correct. There is no 128-bit
// reversal and no shift-by-1 correction of the kind a whole-value reflection
// would need.

#ifdef __cplusplus
extern "C" {
#endif

// Low XLEN bits of the carry-less product of rs1 and rs2.
__attribute__((always_inline))
inline uint32_t vx_clmul(uint32_t a, uint32_t b) {
    uint32_t out;
    __asm__ (".insn r %1, 1, 5, %0, %2, %3" : "=r"(out) : "i"(RISCV_OP), "r"(a), "r"(b));
    return out;
}

// High XLEN bits of the carry-less product of rs1 and rs2.
__attribute__((always_inline))
inline uint32_t vx_clmulh(uint32_t a, uint32_t b) {
    uint32_t out;
    __asm__ (".insn r %1, 3, 5, %0, %2, %3" : "=r"(out) : "i"(RISCV_OP), "r"(a), "r"(b));
    return out;
}

// rs1 with the bits of each byte reversed.
__attribute__((always_inline))
inline uint32_t vx_brev8(uint32_t a) {
    uint32_t out;
    __asm__ (".insn i %1, 5, %0, %2, 0x687" : "=r"(out) : "i"(RISCV_OP_IMM), "r"(a));
    return out;
}

#ifdef __cplusplus
}
#endif

#endif // __VX_GHASH_H__
