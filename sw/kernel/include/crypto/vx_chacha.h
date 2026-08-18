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

#ifdef __cplusplus
}
#endif

#endif // __VX_CHACHA_H__
