#ifndef _TORN_SG16_COMMON_H_
#define _TORN_SG16_COMMON_H_

#include <VX_types.h>

// One value per lane, so the host can see what each lane produced.
typedef struct {
  uint64_t src;   // rs1 source, one word per lane
  uint64_t dst;   // chacha.dr.sg16 result, one word per lane
  uint32_t lanes; // how many lanes the kernel was launched with
} kernel_arg_t;

#endif
