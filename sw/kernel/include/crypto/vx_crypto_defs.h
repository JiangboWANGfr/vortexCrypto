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

#ifndef __VX_CRYPTO_DEFS_H__
#define __VX_CRYPTO_DEFS_H__

// Shared by every crypto intrinsic header so each one can be included on its
// own. These are RISC-V base opcodes, not crypto-specific; they live here only
// because `.insn` needs them spelled out.

#define RISCV_OP        0x33
#define RISCV_OP_IMM    0x13

// Why `.insn` and not `-march`
// ---------------------------
// Every instruction in these headers is a ratified RISC-V encoding, so naming
// the extension in -march would be the obvious way to reach it. It is
// deliberately not done, and the reason is a correctness hazard rather than a
// preference:
//
// Naming an extension in -march lets clang emit ANY instruction of that
// extension anywhere in the program, including in code that has nothing to do
// with cryptography. This design implements only a handful of them. An
// instruction that is not implemented does NOT trap here -- it decodes as some
// other instruction, and RTL and simx do not necessarily agree on which. The
// result would be a silently wrong answer in unrelated code.
//
// Reaching them through explicit asm keeps emission under our control, at no
// cost to the generated code: the encodings are identical either way.
//
// If an extension is ever implemented in full, that is the point at which
// naming it in -march becomes safe -- not before.

#endif // __VX_CRYPTO_DEFS_H__
