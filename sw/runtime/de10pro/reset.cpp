// Standalone DE10-Pro reset: issue AFU CMD_RESET over MMIO and wait for idle.
// Recovers a device whose command processor was wedged by a killed process
// (a FAIL/exit skips ~vx_device's reset), WITHOUT reprogramming or rebooting
// -- the reset path is pure MMIO and does not touch the stuck DMA engine.
#include "driver.h"
#include "vortex_afu.h"
#include <cstdint>
#include <cstdio>
#include <thread>
#include <chrono>


int main() {
  auto handle = drv_open(VX_DE10PRO_DEFAULT_BDF, VX_DE10PRO_DEFAULT_BAR, 0);
  if (handle == nullptr) {
    std::fprintf(stderr, "open failed: %s\n", drv_get_last_error());
    return 1;
  }
  const uint64_t base = VX_DE10PRO_DEFAULT_MMIO_BASE;
  if (!drv_write32(handle, base + AFU_IMAGE_MMIO_CMD_TYPE, AFU_IMAGE_CMD_RESET)) {
    std::fprintf(stderr, "reset write failed: %s\n", drv_get_last_error());
    return 1;
  }
  for (int ms = 0; ms < 5001; ++ms) {
    uint32_t status = 0;
    if (!drv_read32(handle, base + AFU_IMAGE_MMIO_STATUS, &status)) {
      std::fprintf(stderr, "status read failed\n");
      return 1;
    }
    if ((status & 0xFFu) == 0u) {   // low 8 bits == kStateIdle(0)
      std::printf("reset OK: status=0x%x\n", status);
      drv_close(handle);
      return 0;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  std::fprintf(stderr, "reset timed out\n");
  return 1;
}
