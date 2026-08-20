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

#pragma once

#include "func_unit.h"
#include <vector>

#ifdef VX_CFG_EXT_SYM_ENABLE

namespace vortex {

// Symmetric-cipher unit: the simx counterpart of hw/rtl/crypto/sym/VX_sym_unit.sv.
// Must stay bit-exact with hw/rtl/crypto/sym/VX_sym_aes.sv.
class SymUnit : public FuncUnit<VX_CFG_NUM_SYM_BLOCKS> {
public:
  SymUnit(const SimContext& ctx, const char* name, Core*);

protected:
  void on_tick() override;

private:
  void execute(instr_trace_t* trace);

  uint32_t latency_of(const instr_trace_t* trace) const;

#ifdef VX_CFG_EXT_SYM_S2_ENABLE
  // One AES context per (warp, lane). It must be keyed by the warp as well as
  // the lane: warps interleave freely, so a context held per lane alone would
  // be clobbered by whichever warp issued last.
  //
  // The state and the key are packed the way the rest of this unit packs them
  // -- one column per word, row 0 in the low byte -- which is the packing the
  // kernel produces by byte-swapping the host's big-endian round keys.
  // No stored cipher key: software rewrites K before each aes.begin, which is
  // four extra writes per block against 128 bits in every (warp, lane) context.
  struct AesCtx {
    uint32_t s[4] = {0, 0, 0, 0};    // working state, one column per word
    uint32_t k[4] = {0, 0, 0, 0};    // current round key
    uint32_t rnd = 0;                // next round to produce; begin sets 1
    uint32_t k_written = 0;          // one bit per k limb, for the valid check
  };

  std::vector<AesCtx> aes_ctx_;

  AesCtx& ctx_of(uint32_t wid, uint32_t lane) {
    return aes_ctx_[wid * VX_CFG_NUM_THREADS + lane];
  }
#endif

#ifdef VX_CFG_EXT_SYM_CHACHA_S2_ENABLE
  // The whole ChaCha state, plus the key and nonce that let BEGIN rebuild the
  // initial state from a counter alone and CRD add it back on the way out.
  struct ChaCtx {
    uint32_t x[16] = {0};
    uint32_t k[8] = {0};
    uint32_t n[3] = {0};
    uint32_t ctr = 0;
  };

  std::vector<ChaCtx> cha_ctx_;

  ChaCtx& cha_of(uint32_t wid, uint32_t lane) {
    return cha_ctx_[wid * VX_CFG_NUM_THREADS + lane];
  }
#endif
};

}

#endif // VX_CFG_EXT_SYM_ENABLE
