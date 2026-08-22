#ifndef _CHA16_PROBE_COMMON_H_
#define _CHA16_PROBE_COMMON_H_
#include <VX_types.h>
#define CHA16_TRIALS 64
typedef struct { uint64_t in; uint64_t out; uint32_t trials; } kernel_arg_t;
#endif
