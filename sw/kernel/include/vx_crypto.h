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

// Umbrella for the cryptographic intrinsics. One header per algorithm under
// crypto/, because the instruction sets differ per algorithm and an EX unit
// will host more than one of them: EX_SYM holds AES today and ChaCha later,
// EX_AUTH holds GHASH today and Poly1305 later. Splitting by algorithm rather
// than by execute unit therefore survives that growth.
//
// Each header under crypto/ is self-contained and may be included directly if a
// kernel wants only one algorithm. This umbrella exists so that
// vx_intrinsics.h, and any kernel that already includes it, picks up all of
// them without naming each.

#include <crypto/vx_crypto_defs.h>
#include <crypto/vx_aes.h>
#include <crypto/vx_chacha.h>
#include <crypto/vx_ghash.h>

#endif // __VX_CRYPTO_H__
