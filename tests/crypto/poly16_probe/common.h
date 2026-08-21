#ifndef _POLY16_PROBE_COMMON_H_
#define _POLY16_PROBE_COMMON_H_
#include <VX_types.h>

#define POLY16_TRIALS 64

typedef struct {
  uint64_t in;    // per trial: 5 h limbs, 5 r limbs, 16 message words = 26 words
  uint64_t out;   // per trial: 5 result limbs
  uint32_t trials;
} kernel_arg_t;

#define POLY16_IN_WORDS  26
#define POLY16_OUT_WORDS 5
#endif
