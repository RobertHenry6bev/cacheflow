//
//  Test access patterns into the onchip RAMs
//

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "params_kernel.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

static struct cache_sample dummy_sample = {
};
static struct cache_sample * cur_sample = &dummy_sample;

//
// These functions are called to access the hardware.
//
void asm_ramindex_msr(const char *whence, u32 ramindex) {
    printf("ramindex_msr: %8s 0x%08x\n", whence, ramindex);
}

void asm_ramindex_insn_mrs(u32 *ildata, u8 sel) {
    printf("insn_mrs sel=0x%x\n", sel);
    ildata[0] = 0xdead0000UL;
    ildata[1] = 0x1111deadUL;
}

void asm_ramindex_data_mrs(u32 *dldata, u8 sel) {
    printf("data_mrs sel=0x%x\n", sel);
    dldata[0] = 0xdead0000UL;
    dldata[1] = 0x1111deadUL;
    // ...
}

#include "cache_operations.c"

int main(int argc, const char **argv) {
    get_Cortex_L1_Insn();
    if (0) {
        get_Cortex_L1_Tag();
    }
    return 0;
}
