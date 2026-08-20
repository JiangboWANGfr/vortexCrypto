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

#ifndef __VX_CHACHA_H__
#define __VX_CHACHA_H__

#include <stdint.h>
#include <crypto/vx_crypto_defs.h>

// The rotate ChaCha20 is built from -- RISC-V Zbb/Zbkb RORI. Executed by
// EX_SYM (hw/rtl/crypto/sym/VX_sym_rot.sv, sim/simx/sym_unit.cpp).
//
// RORI is a general-purpose instruction, not a cryptographic one, and it is
// grouped here for the same reason brev8 sits in vx_ghash.h: ChaCha20 is what
// motivated implementing it. That distinction is load-bearing when the results
// are read. ChaCha20's quarter-round is add / xor / rotate, and `rv32imaf` has
// no rotate at all, so the software baseline spends slli+srli+or on every one
// of them -- eighty quarter-rounds per 64-byte block, four rotates each, three
// instructions each. Implementing RORI RAISES THE BASELINE. A speedup measured
// against a baseline that lacks it is claiming credit for the B extension, not
// for a cryptographic instruction-set extension.
//
// Only the immediate form is here. ChaCha20's four rotate amounts are
// compile-time constants, so ROL/ROR would have no user; and because shamt is
// an instruction field, these have to be macros rather than functions.

#ifdef __cplusplus
extern "C" {
#endif

// rd = (rs1 >> shamt) | (rs1 << (32 - shamt))
// OP-IMM, funct3 101, imm = {0110000, shamt}.
#define vx_rori(a, shamt) ({                                                 \
    uint32_t __out;                                                          \
    __asm__ (".insn i %1, 5, %0, %2, %3"                                     \
             : "=r"(__out)                                                   \
             : "i"(RISCV_OP_IMM), "r"((uint32_t)(a)),                        \
               "i"(0x600 | ((shamt) & 31)));                                 \
    __out;                                                                   \
})

// ChaCha20 is written in terms of left rotates; there is no ROLI, so this is
// the same instruction addressed from the other side.
#define vx_rotl32(a, n) vx_rori(a, (32 - (n)) & 31)

// ChaCha20's quarter-round never rotates without xoring first:
//
//   d ^= a; d <<<= 16;   b ^= c; b <<<= 12;
//   d ^= a; d <<<=  8;   b ^= c; b <<<=  7;
//
// so the pair always travels together. This fuses them:
//
//   vx_chacha32_xr(a, b, n)  ->  rol32(a ^ b, n)
//
// `n` is the LEFT rotate amount, matching how ChaCha is specified, and unlike
// vx_rori's right amount. It must be a compile-time constant; all four amounts
// ChaCha uses are.
//
// Custom-3 (0x7B) funct3 6, executed by the rotate PE
// (hw/rtl/crypto/sym/VX_sym_rot.sv) -- not the AES one, because this carries no
// S-box, no field arithmetic and no algorithm constant.
#ifdef VX_CFG_EXT_SYM_CHACHA_ENABLE
#define vx_chacha32_xr(a, b, n) ({                                           \
    uint32_t __out;                                                          \
    __asm__ (".insn r %1, 6, %2, %0, %3, %4"                                 \
             : "=r"(__out)                                                   \
             : "i"(0x7B), "i"((n) & 31),                                     \
               "r"((uint32_t)(a)), "r"((uint32_t)(b)));                      \
    __out;                                                                   \
})
#endif

// Poly1305 three-source multiply-accumulate on the 26-bit limbs the software
// already uses. R4-type -- the same shape WGATHER uses -- so rs3 costs no new
// operand path on this machine.
//
//   vx_poly26_macl (acc, a, b)  ->  acc + ((a * (b & 0x3ffffff))      & 0x3ffffff)
//   vx_poly26_mach (acc, a, b)  ->  acc + ((a * (b & 0x3ffffff))      >> 26)
//   vx_poly26_macl5(acc, a, b)  ->  acc + ((a * (b & 0x3ffffff) * 5)  & 0x3ffffff)
//   vx_poly26_mach5(acc, a, b)  ->  acc + ((a * (b & 0x3ffffff) * 5)  >> 26)
//
// `b` is masked to 26 bits, so the *5 forms exist for a reason rather than as a
// convenience: the reduction's wrapped terms carry a factor of five, and the
// usual software trick of precomputing s_i = 5*r_i produces values up to 2^28.3
// that a 26-bit operand cannot hold. Using them keeps the key in five registers
// instead of nine, which in a kernel that already spills is four fewer live
// values rather than four fewer instructions.
//
// The low and high halves accumulate in separate registers and are recombined
// once per output limb. That is exact: the low accumulator sums the products
// modulo 2^26 and the high one sums their quotients.
//
// Custom-2 (0x5B) funct3 5, funct2 = {scale5, high}, executed by EX_AUTH's
// Poly PE (hw/rtl/crypto/auth/VX_auth_poly.sv).
#ifdef VX_CFG_EXT_AUTH_POLY_ENABLE
#define __vx_poly26_mac(acc, a, b, f2) ({                                    \
    uint32_t __out;                                                          \
    __asm__ (".insn r4 %1, 5, %2, %0, %3, %4, %5"                            \
             : "=r"(__out)                                                   \
             : "i"(0x5B), "i"(f2), "r"((uint32_t)(acc)),                     \
               "r"((uint32_t)(a)), "r"((uint32_t)(b)));                      \
    __out;                                                                   \
})

#define vx_poly26_macl(acc, a, b)  __vx_poly26_mac(acc, a, b, 0)
#define vx_poly26_mach(acc, a, b)  __vx_poly26_mac(acc, a, b, 1)
#define vx_poly26_macl5(acc, a, b) __vx_poly26_mac(acc, a, b, 2)
#define vx_poly26_mach5(acc, a, b) __vx_poly26_mac(acc, a, b, 3)
#endif

#ifdef __cplusplus
}
#endif

#endif // __VX_CHACHA_H__
