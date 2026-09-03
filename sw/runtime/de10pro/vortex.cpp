// Copyright © 2019-2023
// Licensed under the Apache License, Version 2.0.

// DE10-Pro transport backend with a software implementation of the Vortex
// command processor. The common runtime writes its normal CP command ring in
// host memory; committing Q_TAIL executes those commands synchronously through
// the Intel Gen3x16 BAR and board-DDR DMA interfaces.

#include <common.h>
#include <de10pro_board_manager_abi.h>

#include "board_manager.h"
#include "driver.h"
#include "vortex_afu.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

using namespace vortex;
using vortex::de10pro::BoardManager;
using vortex::de10pro::BoardManagerIo;
using vortex::de10pro::BoardProbeResult;
using vortex::de10pro::ClockPollResult;
using vortex::de10pro::ClockState;

namespace {

constexpr uint64_t kCacheLineBytes = 64;
constexpr uint32_t kStatusStateBits = 8;
constexpr uint32_t kStateIdle = 0;

constexpr uint32_t kCpRegCtrl = 0x000;
constexpr uint32_t kCpRegStatus = 0x004;
constexpr uint32_t kCpDevCaps = 0x008;
constexpr uint32_t kCpGpuDevCapsLo = 0x018;
constexpr uint32_t kCpGpuDevCapsHi = 0x01c;
constexpr uint32_t kCpGpuIsaCapsLo = 0x020;
constexpr uint32_t kCpGpuIsaCapsHi = 0x024;

constexpr uint32_t kCpQRingBaseLo = 0x100;
constexpr uint32_t kCpQRingBaseHi = 0x104;
constexpr uint32_t kCpQHeadAddrLo = 0x108;
constexpr uint32_t kCpQHeadAddrHi = 0x10c;
constexpr uint32_t kCpQCmplAddrLo = 0x110;
constexpr uint32_t kCpQCmplAddrHi = 0x114;
constexpr uint32_t kCpQRingSizeLog2 = 0x118;
constexpr uint32_t kCpQControl = 0x11c;
constexpr uint32_t kCpQTailLo = 0x120;
constexpr uint32_t kCpQTailHi = 0x124;
constexpr uint32_t kCpQSeqnum = 0x128;
constexpr uint32_t kCpQLastDcrRsp = 0x130;

constexpr uint8_t kCpOpcodeMemWrite = 0x01;
constexpr uint8_t kCpOpcodeMemRead = 0x02;
constexpr uint8_t kCpOpcodeMemCopy = 0x03;
constexpr uint8_t kCpOpcodeDcrWrite = 0x04;
constexpr uint8_t kCpOpcodeDcrRead = 0x05;
constexpr uint8_t kCpOpcodeLaunch = 0x06;
constexpr uint8_t kCpOpcodeCacheFlush = 0x0a;

uint64_t env_u64(const char* name, uint64_t default_value) {
  const char* value = std::getenv(name);
  if (value == nullptr || value[0] == '\0')
    return default_value;
  char* end = nullptr;
  const unsigned long long parsed = std::strtoull(value, &end, 0);
  return (end == value || *end != '\0') ? default_value : parsed;
}

uint32_t env_u32(const char* name, uint32_t default_value) {
  return static_cast<uint32_t>(env_u64(name, default_value));
}

uint32_t load_u32(const uint8_t* ptr) {
  uint32_t value;
  std::memcpy(&value, ptr, sizeof(value));
  return value;
}

uint64_t load_u64(const uint8_t* ptr) {
  uint64_t value;
  std::memcpy(&value, ptr, sizeof(value));
  return value;
}

void set_low_u32(uint64_t* dst, uint32_t value) {
  *dst = (*dst & 0xffffffff00000000ull) | value;
}

void set_high_u32(uint64_t* dst, uint32_t value) {
  *dst = (*dst & 0x00000000ffffffffull) | (uint64_t(value) << 32);
}

} // namespace

class vx_device {
public:
  vx_device()
      : mmio_base_(VX_DE10PRO_DEFAULT_MMIO_BASE),
        staging_addr_(VX_DE10PRO_DEFAULT_STAGING),
        staging_size_(VX_DE10PRO_DEFAULT_CHUNK_SIZE),
        pcie_(nullptr),
        afu_initialized_(false) {}

  ~vx_device() {
    if (pcie_ != nullptr) {
      if (afu_initialized_
       && env_u32("DE10PRO_VX_RESET_ON_CLOSE", 1) != 0)
        (void)mmio_write32(AFU_IMAGE_MMIO_CMD_TYPE,
                           AFU_IMAGE_CMD_RESET);
      drv_close(pcie_);
      pcie_ = nullptr;
    }

    std::lock_guard<std::mutex> guard(host_mutex_);
    for (const auto& region : host_regions_)
      std::free(reinterpret_cast<void*>(region.first));
    host_regions_.clear();
  }

  int init() {
    const uint32_t bdf = env_u32("DE10PRO_PCIE_BDF",
                                 VX_DE10PRO_DEFAULT_BDF);
    const pcie_bar_t bar = static_cast<pcie_bar_t>(
        env_u32("DE10PRO_VX_BAR", VX_DE10PRO_DEFAULT_BAR));

    mmio_base_ = env_u64("DE10PRO_VX_MMIO_BASE",
                         VX_DE10PRO_DEFAULT_MMIO_BASE);
    staging_addr_ = env_u64("DE10PRO_VX_STAGING_ADDR",
                            VX_DE10PRO_DEFAULT_STAGING);
    staging_size_ = aligned_size(
        env_u64("DE10PRO_VX_STAGING_SIZE",
                VX_DE10PRO_DEFAULT_CHUNK_SIZE),
        kCacheLineBytes);
    if (staging_size_ < kCacheLineBytes
     || staging_size_ > VX_DE10PRO_MAX_DMA_SIZE) {
      std::fprintf(stderr,
                   "[VXDRV] invalid DE10PRO_VX_STAGING_SIZE: 0x%llx\n",
                   static_cast<unsigned long long>(staging_size_));
      return -1;
    }

    pcie_ = drv_open(bdf, bar, static_cast<uint32_t>(staging_size_));
    if (pcie_ == nullptr) {
      std::fprintf(stderr, "[VXDRV] PCIe open failed: %s\n",
                   driver_error());
      return -1;
    }

    BoardManagerIo board_io{
        pcie_,
        [](void* context, uint64_t address, uint32_t* value) {
          return drv_read32(context, address, value);
        },
        [](void* context, uint64_t address, uint32_t value) {
          return drv_write32(context, address, value);
        }};
    board_manager_.reset(new BoardManager(board_io));
    const auto probe = board_manager_->probe();
    if (probe == BoardProbeResult::IoError) {
      std::fprintf(stderr,
                   "[VXDRV] DE10-Pro board-manager probe failed: %s\n",
                   driver_error());
      return -1;
    }
    if (probe != BoardProbeResult::Available
     && env_u32("DE10PRO_VX_VERBOSE_STATUS", 0) != 0) {
      std::fprintf(stdout,
                   "[VXDRV] optional DE10-Pro board manager unavailable (%u)\n",
                   static_cast<unsigned int>(probe));
    }
    if (probe == BoardProbeResult::Available
     && board_manager_->supports_clock_control()) {
      ClockState clock_state{};
      if (board_manager_->poll_clock_request(0, &clock_state)
          == ClockPollResult::IoError) {
        std::fprintf(stderr,
                     "[VXDRV] DE10-Pro clock-status read failed: %s\n",
                     driver_error());
        return -1;
      }
      if (clock_state.status & VX_DE10PRO_BM_CLOCK_BUSY) {
        std::fprintf(stderr,
                     "[VXDRV] DE10-Pro clock change is still in progress\n");
        return -1;
      }
    }

    if (mmio_read64(AFU_IMAGE_MMIO_DEV_CAPS, &gpu_dev_caps_) != 0
     || mmio_read64(AFU_IMAGE_MMIO_ISA_CAPS, &gpu_isa_caps_) != 0) {
      return -1;
    }

    if (mmio_write32(AFU_IMAGE_MMIO_CMD_TYPE,
                     AFU_IMAGE_CMD_RESET) != 0) {
      return -1;
    }
    if (wait_idle() != 0) {
      return -1;
    }
    afu_initialized_ = true;
    return 0;
  }

  int platform_query(uint32_t query_id, uint64_t* value) {
    if (value == nullptr || query_id != VX_PLATFORM_QUERY_CLOCK_RATE_HZ
     || board_manager_ == nullptr || !board_manager_->available()) {
      return VX_PLATFORM_QUERY_NOT_SUPPORTED;
    }
    if (!(board_manager_->capabilities()
        & VX_DE10PRO_BM_CAP_CLOCK_READBACK)) {
      return VX_PLATFORM_QUERY_NOT_SUPPORTED;
    }
    uint32_t frequency_hz = 0;
    if (!board_manager_->read_current_clock_hz(&frequency_hz)) {
      return -1;
    }
    *value = frequency_hz;
    return 0;
  }

  int cp_reg_write(uint32_t off, uint32_t value) {
    std::lock_guard<std::mutex> guard(cp_mutex_);
    switch (off) {
    case kCpRegCtrl:
      cp_ctrl_ = value & ~2u;
      if (value & 2u)
        reset_queue_state();
      return 0;
    case kCpQRingBaseLo:
      set_low_u32(&ring_base_, value);
      return 0;
    case kCpQRingBaseHi:
      set_high_u32(&ring_base_, value);
      return 0;
    case kCpQHeadAddrLo:
      set_low_u32(&head_addr_, value);
      return 0;
    case kCpQHeadAddrHi:
      set_high_u32(&head_addr_, value);
      return 0;
    case kCpQCmplAddrLo:
      set_low_u32(&cmpl_addr_, value);
      return 0;
    case kCpQCmplAddrHi:
      set_high_u32(&cmpl_addr_, value);
      return 0;
    case kCpQRingSizeLog2:
      ring_size_log2_ = value;
      return 0;
    case kCpQControl:
      q_control_ = value & ~2u;
      if (value & 2u)
        reset_queue_state();
      return 0;
    case kCpQTailLo:
      tail_low_staging_ = value;
      return 0;
    case kCpQTailHi:
      committed_tail_ = (uint64_t(value) << 32) | tail_low_staging_;
      return process_committed_tail();
    default:
      std::fprintf(stderr,
                   "[VXDRV] unsupported DE10-Pro CP register write: 0x%x\n",
                   off);
      return -1;
    }
  }

  int cp_reg_read(uint32_t off, uint32_t* value) {
    if (value == nullptr)
      return -1;
    std::lock_guard<std::mutex> guard(cp_mutex_);
    switch (off) {
    case kCpRegCtrl:
      *value = cp_ctrl_;
      return 0;
    case kCpRegStatus:
      *value = 0;
      return 0;
    case kCpDevCaps:
      // One queue, maximum ring log2=16, no VM/DRAW/QMD feature bits.
      *value = 1u | (16u << 8);
      return 0;
    case kCpGpuDevCapsLo:
      *value = static_cast<uint32_t>(gpu_dev_caps_);
      return 0;
    case kCpGpuDevCapsHi:
      *value = static_cast<uint32_t>(gpu_dev_caps_ >> 32);
      return 0;
    case kCpGpuIsaCapsLo:
      *value = static_cast<uint32_t>(gpu_isa_caps_);
      return 0;
    case kCpGpuIsaCapsHi:
      *value = static_cast<uint32_t>(gpu_isa_caps_ >> 32);
      return 0;
    case kCpQSeqnum:
      *value = static_cast<uint32_t>(seqnum_);
      return 0;
    case kCpQLastDcrRsp:
      *value = last_dcr_rsp_;
      return 0;
    default:
      std::fprintf(stderr,
                   "[VXDRV] unsupported DE10-Pro CP register read: 0x%x\n",
                   off);
      return -1;
    }
  }

  int host_mem_alloc(uint64_t size, void** host_ptr, uint64_t* cp_addr) {
    if (size == 0 || host_ptr == nullptr || cp_addr == nullptr)
      return -1;
    if (size > std::numeric_limits<uint64_t>::max()
             - (kCacheLineBytes - 1))
      return -1;
    const uint64_t alloc_size = aligned_size(size, kCacheLineBytes);
    if (alloc_size > std::numeric_limits<size_t>::max())
      return -1;
    void* ptr = std::aligned_alloc(kCacheLineBytes,
                                   static_cast<size_t>(alloc_size));
    if (ptr == nullptr)
      return -1;

    const uint64_t addr = reinterpret_cast<uint64_t>(ptr);
    {
      std::lock_guard<std::mutex> guard(host_mutex_);
      host_regions_[addr] = alloc_size;
    }
    *host_ptr = ptr;
    *cp_addr = addr;
    return 0;
  }

  int host_mem_free(uint64_t cp_addr) {
    void* ptr = nullptr;
    {
      std::lock_guard<std::mutex> guard(host_mutex_);
      const auto it = host_regions_.find(cp_addr);
      if (it == host_regions_.end())
        return -1;
      ptr = reinterpret_cast<void*>(it->first);
      host_regions_.erase(it);
    }
    std::free(ptr);
    return 0;
  }

private:
  const char* driver_error() const {
    return drv_get_last_error();
  }

  int mmio_read32(uint64_t reg, uint32_t* value) const {
    if (!drv_read32(pcie_, mmio_base_ + reg, value)) {
      std::fprintf(stderr,
                   "[VXDRV] PCIE_Read32(reg=0x%llx) failed: %s\n",
                   static_cast<unsigned long long>(reg), driver_error());
      return -1;
    }
    return 0;
  }

  int mmio_write32(uint64_t reg, uint32_t value) const {
    if (!drv_write32(pcie_, mmio_base_ + reg, value)) {
      std::fprintf(stderr,
                   "[VXDRV] PCIE_Write32(reg=0x%llx, value=0x%x) failed: %s\n",
                   static_cast<unsigned long long>(reg), value,
                   driver_error());
      return -1;
    }
    return 0;
  }

  int mmio_read64(uint64_t reg, uint64_t* value) const {
    uint32_t low = 0;
    uint32_t high = 0;
    if (mmio_read32(reg, &low) != 0
     || mmio_read32(reg + sizeof(uint32_t), &high) != 0)
      return -1;
    *value = uint64_t(low) | (uint64_t(high) << 32);
    return 0;
  }

  int mmio_write64(uint64_t reg, uint64_t value) const {
    if (mmio_write32(reg, static_cast<uint32_t>(value)) != 0
     || mmio_write32(reg + sizeof(uint32_t),
                     static_cast<uint32_t>(value >> 32)) != 0)
      return -1;
    return 0;
  }

  void* resolve_host_range(uint64_t addr, uint64_t size) {
    if (size == 0)
      return reinterpret_cast<void*>(addr);
    std::lock_guard<std::mutex> guard(host_mutex_);
    auto it = host_regions_.upper_bound(addr);
    if (it == host_regions_.begin())
      return nullptr;
    --it;
    const uint64_t offset = addr - it->first;
    if (addr < it->first || offset > it->second
     || size > it->second - offset)
      return nullptr;
    return reinterpret_cast<void*>(addr);
  }

  bool valid_device_range(uint64_t addr, uint64_t size) const {
    const uint64_t memory_size = uint64_t(GLOBAL_MEM_SIZE);
    return addr <= memory_size && size <= memory_size - addr
        && staging_addr_ <= std::numeric_limits<uint64_t>::max() - addr;
  }

  int dma_read_raw(uint64_t dev_addr, void* dst, uint64_t size) {
    if (size > std::numeric_limits<uint32_t>::max()
     || staging_addr_ > std::numeric_limits<uint64_t>::max() - dev_addr)
      return -1;
    const uint64_t local_addr = staging_addr_ + dev_addr;
    if (size > std::numeric_limits<uint64_t>::max() - local_addr)
      return -1;
    if (!drv_dma_read(pcie_, local_addr, dst,
                           static_cast<uint32_t>(size))) {
      std::fprintf(stderr,
                   "[VXDRV] PCIE_DmaRead(dev=0x%llx, size=0x%llx) failed: %s\n",
                   static_cast<unsigned long long>(dev_addr),
                   static_cast<unsigned long long>(size), driver_error());
      return -1;
    }
    return 0;
  }

  int dma_write_raw(uint64_t dev_addr, const void* src, uint64_t size) {
    if (size > std::numeric_limits<uint32_t>::max()
     || staging_addr_ > std::numeric_limits<uint64_t>::max() - dev_addr)
      return -1;
    const uint64_t local_addr = staging_addr_ + dev_addr;
    if (size > std::numeric_limits<uint64_t>::max() - local_addr)
      return -1;
    if (!drv_dma_write(pcie_, local_addr, src,
                            static_cast<uint32_t>(size))) {
      std::fprintf(stderr,
                   "[VXDRV] PCIE_DmaWrite(dev=0x%llx, size=0x%llx) failed: %s\n",
                   static_cast<unsigned long long>(dev_addr),
                   static_cast<unsigned long long>(size), driver_error());
      return -1;
    }
    return 0;
  }

  int dma_upload(uint64_t dev_addr, const void* src_void, uint64_t size) {
    if (size == 0)
      return 0;
    if (src_void == nullptr || !valid_device_range(dev_addr, size))
      return -1;

    const auto* src = static_cast<const uint8_t*>(src_void);
    std::vector<uint8_t> scratch;
    uint64_t done = 0;
    while (done < size) {
      const uint64_t current = dev_addr + done;
      const uint64_t aligned_addr = current & ~(kCacheLineBytes - 1);
      const uint64_t prefix = current - aligned_addr;
      const uint64_t payload = std::min(size - done,
                                        staging_size_ - prefix);
      const uint64_t dma_size = aligned_size(prefix + payload,
                                             kCacheLineBytes);

      if (prefix == 0 && payload == dma_size) {
        if (dma_write_raw(aligned_addr, src + done, dma_size) != 0)
          return -1;
      } else {
        scratch.resize(static_cast<size_t>(dma_size));
        if (dma_read_raw(aligned_addr, scratch.data(), dma_size) != 0)
          return -1;
        std::memcpy(scratch.data() + prefix, src + done,
                    static_cast<size_t>(payload));
        if (dma_write_raw(aligned_addr, scratch.data(), dma_size) != 0)
          return -1;
      }
      done += payload;
    }
    return 0;
  }

  int dma_download(void* dst_void, uint64_t dev_addr, uint64_t size) {
    if (size == 0)
      return 0;
    if (dst_void == nullptr || !valid_device_range(dev_addr, size))
      return -1;

    auto* dst = static_cast<uint8_t*>(dst_void);
    std::vector<uint8_t> scratch;
    uint64_t done = 0;
    while (done < size) {
      const uint64_t current = dev_addr + done;
      const uint64_t aligned_addr = current & ~(kCacheLineBytes - 1);
      const uint64_t prefix = current - aligned_addr;
      const uint64_t payload = std::min(size - done,
                                        staging_size_ - prefix);
      const uint64_t dma_size = aligned_size(prefix + payload,
                                             kCacheLineBytes);

      if (prefix == 0 && payload == dma_size) {
        if (dma_read_raw(aligned_addr, dst + done, dma_size) != 0)
          return -1;
      } else {
        scratch.resize(static_cast<size_t>(dma_size));
        if (dma_read_raw(aligned_addr, scratch.data(), dma_size) != 0)
          return -1;
        std::memcpy(dst + done, scratch.data() + prefix,
                    static_cast<size_t>(payload));
      }
      done += payload;
    }
    return 0;
  }

  int dma_copy(uint64_t dst, uint64_t src, uint64_t size) {
    if (size == 0 || dst == src)
      return 0;
    if (!valid_device_range(src, size)
     || !valid_device_range(dst, size))
      return -1;

    std::vector<uint8_t> bounce(static_cast<size_t>(staging_size_));
    const bool copy_backward = dst > src && dst - src < size;
    if (copy_backward) {
      uint64_t remaining = size;
      while (remaining != 0) {
        const uint64_t chunk = std::min(remaining, staging_size_);
        const uint64_t offset = remaining - chunk;
        if (dma_download(bounce.data(), src + offset, chunk) != 0
         || dma_upload(dst + offset, bounce.data(), chunk) != 0)
          return -1;
        remaining = offset;
      }
    } else {
      uint64_t offset = 0;
      while (offset < size) {
        const uint64_t chunk = std::min(size - offset, staging_size_);
        if (dma_download(bounce.data(), src + offset, chunk) != 0
         || dma_upload(dst + offset, bounce.data(), chunk) != 0)
          return -1;
        offset += chunk;
      }
    }
    return 0;
  }

  int dcr_write(uint32_t addr, uint32_t value) {
    if (mmio_write64(AFU_IMAGE_MMIO_CMD_ARG0, addr) != 0
     || mmio_write64(AFU_IMAGE_MMIO_CMD_ARG1, value) != 0
     || mmio_write32(AFU_IMAGE_MMIO_CMD_TYPE,
                     AFU_IMAGE_CMD_DCR_WRITE) != 0)
      return -1;
    return 0;
  }

  int dcr_read(uint32_t addr, uint32_t tag, uint32_t* value) {
    if (value == nullptr)
      return -1;
    // Clear the previous valid flag before ringing the DCR-read doorbell.
    if (mmio_write64(AFU_IMAGE_MMIO_CMD_ARG2, 0) != 0
     || mmio_write64(AFU_IMAGE_MMIO_CMD_ARG0, addr) != 0
     || mmio_write64(AFU_IMAGE_MMIO_CMD_ARG1, tag) != 0
     || mmio_write32(AFU_IMAGE_MMIO_CMD_TYPE,
                     AFU_IMAGE_CMD_DCR_READ) != 0)
      return -1;

    const uint64_t timeout_ms = env_u64("DE10PRO_VX_TIMEOUT_MS",
                                        VX_MAX_TIMEOUT);
    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(timeout_ms);
    for (;;) {
      uint32_t valid_word = 0;
      if (mmio_read32(AFU_IMAGE_MMIO_CMD_ARG2 + sizeof(uint32_t),
                      &valid_word) != 0)
        return -1;
      constexpr uint32_t valid_mask =
          1u << (AFU_IMAGE_DCR_READ_VALID_BIT - 32);
      if (valid_word & valid_mask)
        return mmio_read32(AFU_IMAGE_MMIO_CMD_ARG2, value);
      if (timeout_ms == 0 || std::chrono::steady_clock::now() >= deadline) {
        std::fprintf(stderr,
                     "[VXDRV] DCR read timed out: addr=0x%x, tag=0x%x\n",
                     addr, tag);
        return -1;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }

  int wait_idle() {
    const uint64_t timeout_ms = env_u64("DE10PRO_VX_TIMEOUT_MS",
                                        VX_MAX_TIMEOUT);
    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(timeout_ms);
    for (;;) {
      uint64_t status = 0;
      if (mmio_read64(AFU_IMAGE_MMIO_STATUS, &status) != 0)
        return -1;
      if ((status & ((1u << kStatusStateBits) - 1)) == kStateIdle)
        return 0;
      if (timeout_ms == 0 || std::chrono::steady_clock::now() >= deadline) {
        std::fprintf(stderr,
                     "[VXDRV] DE10-Pro reset timed out: status=0x%llx\n",
                     static_cast<unsigned long long>(status));
        return -1;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }

  int launch_and_wait() {
    uint64_t initial_status = 0;
    if (mmio_read64(AFU_IMAGE_MMIO_STATUS, &initial_status) != 0)
      return -1;
    const uint32_t initial_seq = static_cast<uint32_t>(
        initial_status >> AFU_IMAGE_STATUS_LAUNCH_SEQ_SHIFT);

    if (mmio_write32(AFU_IMAGE_MMIO_CMD_TYPE, AFU_IMAGE_CMD_RUN) != 0)
      return -1;

    const uint64_t timeout_ms = env_u64("DE10PRO_VX_TIMEOUT_MS",
                                        VX_MAX_TIMEOUT);
    const bool verbose = env_u32("DE10PRO_VX_VERBOSE_STATUS", 0) != 0;
    const auto start = std::chrono::steady_clock::now();
    const auto deadline = start + std::chrono::milliseconds(timeout_ms);
    uint32_t last_state = std::numeric_limits<uint32_t>::max();

    for (;;) {
      uint64_t status = 0;
      if (mmio_read64(AFU_IMAGE_MMIO_STATUS, &status) != 0)
        return -1;
      const uint32_t state = status & ((1u << kStatusStateBits) - 1);
      if (verbose && state != last_state) {
        std::fprintf(stdout,
                     "[VXDRV] DE10-Pro state=%u, status=0x%llx\n",
                     state, static_cast<unsigned long long>(status));
        last_state = state;
      }
      const uint32_t launch_seq = static_cast<uint32_t>(
          status >> AFU_IMAGE_STATUS_LAUNCH_SEQ_SHIFT);
      if (launch_seq != initial_seq)
        return 0;

      if (timeout_ms == 0 || std::chrono::steady_clock::now() >= deadline) {
        const auto elapsed = std::chrono::duration_cast<
            std::chrono::milliseconds>(std::chrono::steady_clock::now()
                                      - start).count();
        std::fprintf(stderr,
                     "[VXDRV] launch timed out: state=%u, elapsed=%lld ms, status=0x%llx\n",
                     state, static_cast<long long>(elapsed),
                     static_cast<unsigned long long>(status));
        return -1;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }

  int execute_command(const uint8_t* cl) {
    const uint8_t opcode = cl[0];
    const uint64_t arg0 = load_u64(cl + 4);
    const uint64_t arg1 = load_u64(cl + 12);
    const uint64_t arg2 = load_u64(cl + 20);

    switch (opcode) {
    case kCpOpcodeMemWrite: {
      void* host_src = resolve_host_range(arg1, arg2);
      return host_src ? dma_upload(arg0, host_src, arg2) : -1;
    }
    case kCpOpcodeMemRead: {
      void* host_dst = resolve_host_range(arg0, arg2);
      return host_dst ? dma_download(host_dst, arg1, arg2) : -1;
    }
    case kCpOpcodeMemCopy:
      return dma_copy(arg0, arg1, arg2);
    case kCpOpcodeDcrWrite:
      return dcr_write(load_u32(cl + 4), load_u32(cl + 12));
    case kCpOpcodeDcrRead: {
      uint32_t response = 0;
      const int ret = dcr_read(load_u32(cl + 4), load_u32(cl + 12),
                               &response);
      if (ret == 0)
        last_dcr_rsp_ = response;
      return ret;
    }
    case kCpOpcodeLaunch:
      return launch_and_wait();
    case kCpOpcodeCacheFlush: {
      if (arg0 > std::numeric_limits<uint32_t>::max())
        return -1;
      for (uint32_t core_id = 0; core_id < uint32_t(arg0); ++core_id) {
        uint32_t ignored = 0;
        if (dcr_read(VX_DCR_BASE_CACHE_FLUSH, core_id, &ignored) != 0)
          return -1;
      }
      return 0;
    }
    default:
      std::fprintf(stderr,
                   "[VXDRV] unsupported software-CP opcode 0x%x\n",
                   opcode);
      return -1;
    }
  }

  int write_queue_telemetry() {
    if (head_addr_ != 0) {
      void* head = resolve_host_range(head_addr_, sizeof(consumed_head_));
      if (head == nullptr)
        return -1;
      std::memcpy(head, &consumed_head_, sizeof(consumed_head_));
    }
    if (cmpl_addr_ != 0) {
      void* completion = resolve_host_range(cmpl_addr_, sizeof(seqnum_));
      if (completion == nullptr)
        return -1;
      std::memcpy(completion, &seqnum_, sizeof(seqnum_));
    }
    return 0;
  }

  int process_committed_tail() {
    if (!(cp_ctrl_ & 1u) || !(q_control_ & 1u)) {
      std::fprintf(stderr, "[VXDRV] software CP queue is not enabled\n");
      return -1;
    }
    if (ring_size_log2_ < 6 || ring_size_log2_ > 16
     || (committed_tail_ & (kCacheLineBytes - 1)) != 0
     || committed_tail_ < consumed_head_) {
      std::fprintf(stderr,
                   "[VXDRV] invalid software-CP ring state: head=0x%llx tail=0x%llx log2=%u\n",
                   static_cast<unsigned long long>(consumed_head_),
                   static_cast<unsigned long long>(committed_tail_),
                   ring_size_log2_);
      return -1;
    }

    const uint64_t ring_size = uint64_t(1) << ring_size_log2_;
    if (committed_tail_ - consumed_head_ > ring_size) {
      std::fprintf(stderr, "[VXDRV] software-CP ring overrun\n");
      return -1;
    }

    while (consumed_head_ < committed_tail_) {
      const uint64_t ring_offset = consumed_head_ & (ring_size - 1);
      void* ring_ptr = resolve_host_range(ring_base_ + ring_offset,
                                          kCacheLineBytes);
      if (ring_ptr == nullptr) {
        std::fprintf(stderr,
                     "[VXDRV] invalid software-CP ring address: 0x%llx\n",
                     static_cast<unsigned long long>(ring_base_ + ring_offset));
        return -1;
      }

      uint8_t cl[kCacheLineBytes];
      std::memcpy(cl, ring_ptr, sizeof(cl));
      if (execute_command(cl) != 0) {
        std::fprintf(stderr,
                     "[VXDRV] software-CP command failed: opcode=0x%x head=0x%llx\n",
                     cl[0], static_cast<unsigned long long>(consumed_head_));
        return -1;
      }

      consumed_head_ += kCacheLineBytes;
      ++seqnum_;
      if (write_queue_telemetry() != 0) {
        std::fprintf(stderr,
                     "[VXDRV] invalid software-CP queue telemetry address\n");
        return -1;
      }
    }
    return 0;
  }

  void reset_queue_state() {
    committed_tail_ = 0;
    consumed_head_ = 0;
    seqnum_ = 0;
    last_dcr_rsp_ = 0;
  }

  uint64_t mmio_base_;
  uint64_t staging_addr_;
  uint64_t staging_size_;
  pcie_handle_t pcie_;
  bool afu_initialized_;
  std::unique_ptr<BoardManager> board_manager_;

  std::mutex host_mutex_;
  std::map<uint64_t, uint64_t> host_regions_;

  std::mutex cp_mutex_;
  uint32_t cp_ctrl_ = 0;
  uint64_t ring_base_ = 0;
  uint64_t head_addr_ = 0;
  uint64_t cmpl_addr_ = 0;
  uint32_t ring_size_log2_ = 0;
  uint32_t q_control_ = 0;
  uint32_t tail_low_staging_ = 0;
  uint64_t committed_tail_ = 0;
  uint64_t consumed_head_ = 0;
  uint64_t seqnum_ = 0;
  uint32_t last_dcr_rsp_ = 0;

  uint64_t gpu_dev_caps_ = 0;
  uint64_t gpu_isa_caps_ = 0;
};

// Power telemetry for measurement hosts, resolved by dlsym so the crypto
// applications stay driver-portable. Opens its own BAR-only handle lazily
// (kmem_size 0: plain register reads, no DMA staging) and keeps it for the
// life of the process. Callers serialise sampling with their own device
// traffic; the measurement hosts do so by sampling between kernel launches
// on one thread, so telemetry never races the command processor.
extern "C" int vx_de10pro_power_sample(uint64_t* input_uw, uint64_t* core_uw) {
  using vortex::de10pro::BoardManager;
  using vortex::de10pro::BoardManagerIo;
  using vortex::de10pro::BoardProbeResult;
  using vortex::de10pro::BoardTelemetry;
  static BoardManager* manager = nullptr;
  if (manager == nullptr) {
    const uint32_t bdf = env_u32("DE10PRO_PCIE_BDF", VX_DE10PRO_DEFAULT_BDF);
    const auto bar = static_cast<pcie_bar_t>(
        env_u32("DE10PRO_VX_BAR", VX_DE10PRO_DEFAULT_BAR));
    pcie_handle_t handle = drv_open(bdf, bar, 0);
    if (handle == nullptr) {
      return -1;
    }
    auto candidate = new BoardManager(BoardManagerIo{
        handle,
        [](void* context, uint64_t address, uint32_t* value) {
          return drv_read32(context, address, value);
        },
        [](void* context, uint64_t address, uint32_t value) {
          return drv_write32(context, address, value);
        }});
    if (candidate->probe() != BoardProbeResult::Available) {
      delete candidate;
      return -1;
    }
    manager = candidate;
  }
  BoardTelemetry telemetry{};
  if (!manager->read_telemetry(&telemetry)) {
    return -1;
  }
  *input_uw = BoardManager::power_raw_to_microwatts(telemetry.power_raw[0],
                                                    telemetry.power_lsb_nw[0]);
  *core_uw = BoardManager::power_raw_to_microwatts(telemetry.power_raw[1],
                                                   telemetry.power_lsb_nw[1]);
  return 0;
}

#define VX_BACKEND_HAS_PLATFORM_QUERY
#include <callbacks.inc>
