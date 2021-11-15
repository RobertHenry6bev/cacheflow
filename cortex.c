#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>

#include <linux/types.h>

#include "params_kernel.h"
int main(int argc, const char **argv) {
  printf("sizeof Cortex_L1_I_Insn_Cache = %lu\n",
    sizeof(struct Cortex_L1_I_Insn_Cache));
  printf("sizeof cache_sample = %lu\n",
    sizeof(struct cache_sample));
  return 0;
}
