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

#ifdef VX_CFG_EXT_AUTH_ENABLE

namespace vortex {

// Authentication-MAC unit: the simx counterpart of hw/rtl/crypto/auth/VX_auth_unit.sv.
// Must stay bit-exact with hw/rtl/crypto/auth/VX_auth_ghash.sv.
class AuthUnit : public FuncUnit<VX_CFG_NUM_AUTH_BLOCKS> {
public:
  AuthUnit(const SimContext& ctx, const char* name, Core*);

protected:
  void on_tick() override;

private:
  void execute(instr_trace_t* trace);

  uint32_t latency_of(const instr_trace_t* trace) const;

#ifdef VX_CFG_EXT_AUTH_S2_ENABLE
  // One GHASH context per (warp, lane), for the same reason the AES engine
  // needs one: warps interleave, so a per-lane context alone would be shared
  // between them. All three fields are held in the reflected limb domain the
  // rest of this unit already uses, so the kernel's brev8 conventions do not
  // change.
  struct GhCtx {
    uint32_t h[4] = {0, 0, 0, 0};
    uint32_t y[4] = {0, 0, 0, 0};
    uint32_t x[4] = {0, 0, 0, 0};
    uint32_t h_written = 0;   // one bit per H limb, for the valid check
  };

  std::vector<GhCtx> gh_ctx_;

  GhCtx& ctx_of(uint32_t wid, uint32_t lane) {
    return gh_ctx_[wid * VX_CFG_NUM_THREADS + lane];
  }
#endif
};

}

#endif // VX_CFG_EXT_AUTH_ENABLE
