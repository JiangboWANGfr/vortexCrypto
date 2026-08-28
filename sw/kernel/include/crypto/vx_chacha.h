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

// S3-Fused: the fixed cross-lane communication the subgroup layout introduces,
// folded into the operations that were already there.
//
// ChaCha's diagonal round reads ALL EIGHT of its operands from the next lane of
// the quad -- the D of diagonal j lives in lane j+3 and reads A from lane j,
// and -3 == +1 mod 4 -- so one route direction covers the whole round and the
// six explicit rotations per double-round disappear.
//
//   vx_chadd_sg4(a, b)          -> a + b[lane+1]
//   vx_chacha32_xr_sg4(a, b, n) -> rol32(a ^ b[lane+1], n)
//   vx_poly26_rsum_sg4(v)       -> v[0]+v[1]+v[2]+v[3] of the quad, in every lane
//
// All three require a CONVERGED quad: the source lanes' masks are not
// consulted, matching aesrm.sg4 and ghmul.sg4 rather than SHFL. rsum's inputs
// must already be below 2^26 so that four of them cannot wrap 32 bits.
#ifdef VX_CFG_EXT_SYM_CHACHA_SG4_ENABLE
#define vx_chadd_sg4(a, b) ({                                                \
    uint32_t __out;                                                          \
    __asm__ (".insn r %1, 7, 0, %0, %2, %3"                                  \
             : "=r"(__out)                                                   \
             : "i"(0x7B), "r"((uint32_t)(a)), "r"((uint32_t)(b)));           \
    __out;                                                                   \
})

#define vx_chacha32_xr_sg4(a, b, n) ({                                       \
    uint32_t __out;                                                          \
    __asm__ (".insn r %1, 6, %2, %0, %3, %4"                                 \
             : "=r"(__out)                                                   \
             : "i"(0x7B), "i"(0x20 | ((n) & 31)),                            \
               "r"((uint32_t)(a)), "r"((uint32_t)(b)));                      \
    __out;                                                                   \
})
#endif

#ifdef VX_CFG_EXT_AUTH_POLY_SG4_ENABLE
#define vx_poly26_rsum_sg4(v) ({                                             \
    uint32_t __out;                                                          \
    __asm__ (".insn r %1, 6, 0, %0, %2, x0"                                  \
             : "=r"(__out)                                                   \
             : "i"(0x5B), "r"((uint32_t)(v)));                               \
    __out;                                                                   \
})
#endif

// poly4.step.sg16: one aligned sixteen-lane subgroup absorbs a whole 64-byte
// ChaCha block -- four Poly1305 blocks -- in a single instruction.
//
//   vx_poly4_step_sg16(hr, m)
//
//     lane 0..4  hr -> h0..h4, the accumulator's five 26-bit limbs
//     lane 5..9  hr -> r0..r4, the key's
//     lane 0..15 m  -> one message word each, sixteen words = 64 bytes
//     lane 0..4  rd -> the new accumulator, lanes 5..9 r unchanged so that rd
//                      feeds straight back in, lanes 10..15 zero
//
// h and r are five limbs each and the subgroup is sixteen lanes wide, so both
// fit one register with six lanes to spare. Packing them makes this 2R1W at
// the same instruction count, and r is loop-invariant: the packed value is
// built once per message, not once per block.
//
// The r^2, r^3 and r^4 that the software block-parallel form needs stay inside
// the unit. That schedule is not part of Poly1305's state, only of one way of
// computing it, and measured on the s3f_norp diagnostic it costs twenty loads
// per block and 36% of the kernel's cycles.
//
// PRECONDITION: all sixteen lanes converged. The subgroup's mask must be
// 0xffff, and both models assert it.
#ifdef VX_CFG_EXT_AUTH_POLY_STEP16_ENABLE
#define vx_poly4_step_sg16(hr, m) ({                                         \
    uint32_t __out;                                                          \
    __asm__ (".insn r %1, 7, 0, %0, %2, %3"                                  \
             : "=r"(__out)                                                   \
             : "i"(0x5B), "r"((uint32_t)(hr)), "r"((uint32_t)(m)));          \
    __out;                                                                   \
})
#endif

// chacha.dr.sg16: one aligned sixteen-lane subgroup holds one 512-bit ChaCha20
// state, lane i carrying word i, and one instruction advances a full
// double-round.
//
//   vx_chacha_dr_sg16(x)  -> the lane's word of the state after one double-round
//
// Single source, single destination, no hidden context -- which is the design's
// claim against the stateful engine below: that one buys a low load count with
// 57,344 bits of per-(warp, lane) state, this one with a register per lane.
//
// PRECONDITION: all sixteen lanes converged; both models assert it. Mutually
// exclusive with the S2 engine, which shares its op_type slot.
#ifdef VX_CFG_EXT_SYM_CHACHA_SG16_ENABLE
#define vx_chacha_dr_sg16(x) ({                                              \
    uint32_t __out;                                                          \
    __asm__ (".insn r %1, 3, 0, %0, %2, x0"                                  \
             : "=r"(__out)                                                   \
             : "i"(0x2B), "r"((uint32_t)(x)));                               \
    __out;                                                                   \
})
#endif

// chacha.arx.sg16: one quarter-round line of a sixteen-lane subgroup, stateless
// and combinational -- the direct analogue of aesrm.sg4.
//
//   vx_chacha_arx_sg16(x, line)   line 0..3 = column round, 4..7 = diagonal
//
// Eighty per 64-byte block against vx_chacha_dr_sg16's ten. Mutually exclusive
// with it; the two share an op_type slot and are alternatives.
#ifdef VX_CFG_EXT_SYM_CHACHA_ARX16_ENABLE
#define vx_chacha_arx_sg16(x, line) ({                                       \
    uint32_t __out;                                                          \
    __asm__ (".insn r %1, 3, %2, %0, %3, x0"                                 \
             : "=r"(__out)                                                   \
             : "i"(0x2B), "i"((line) & 7), "r"((uint32_t)(x)));              \
    __out;                                                                   \
})
#endif

// Stateful per-lane ChaCha20 engine (section 23 of the crypto proposal). One
// lane holds a whole 512-bit state in a context keyed by (warp, lane) and one
// instruction advances a double-round.
//
//   vx_cha_cwr(v, sel)   sel 0..7 key word, 8..10 nonce word; once per message
//   vx_cha_begin(ctr)    rebuilds the initial state from the stored key, nonce
//                        and this counter -- a block costs no context writes
//   vx_cha_dr()          one double-round, eight quarter-rounds
//   vx_cha_crd(sel)      x[sel] + init[sel], so ChaCha's feed-forward is folded
//                        into the read and there is no final instruction
//
// Custom-1 (0x2B) funct3 1, funct7[6:5] the class and funct7[3:0] the word --
// a sixteen-word state needs four bits of selector, which the crypto opcodes'
// three-bit field could not hold. `sel` must be a compile-time constant.
//
// Everything but the read is encoded rd = x0, so ordering comes from the unit
// rather than the scoreboard; the volatile asm is what keeps the compiler from
// reordering the chain.
#ifdef VX_CFG_EXT_SYM_CHACHA_S2_ENABLE
#define vx_cha_cwr(v, sel)                                                   \
    __asm__ volatile (".insn r %0, 1, %1, x0, %2, x0"                        \
                      :: "i"(0x2B), "i"((sel) & 0xf), "r"((uint32_t)(v)))

#define vx_cha_begin(ctr)                                                    \
    __asm__ volatile (".insn r %0, 1, %1, x0, %2, x0"                        \
                      :: "i"(0x2B), "i"(0x40), "r"((uint32_t)(ctr)))

#define vx_cha_dr()                                                          \
    __asm__ volatile (".insn r %0, 1, %1, x0, x0, x0"                        \
                      :: "i"(0x2B), "i"(0x60))

#define vx_cha_crd(sel) ({                                                   \
    uint32_t __out;                                                          \
    __asm__ volatile (".insn r %1, 1, %2, %0, x0, x0"                        \
                      : "=r"(__out) : "i"(0x2B), "i"(0x20 | ((sel) & 0xf))); \
    __out; })
#endif

#ifdef __cplusplus
}
#endif

#endif // __VX_CHACHA_H__
