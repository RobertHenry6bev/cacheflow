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
}

#define DO_GET
// #define DO_PRINT

#include "cache_operations.c"

int main(int argc, const char **argv) {
    if (0) {
        printf("MASK2(4,0) = 0x%08lx\n", MASK2(4,0));
        printf("MASK2(3,0) = 0x%08lx\n", MASK2(3,0));
        printf("MASK2(2,0) = 0x%08lx\n", MASK2(2,0));
        printf("MASK2(1,0) = 0x%08lx\n", MASK2(1,0));
        printf("MASK2(0,0) = 0x%08lx\n", MASK2(0,0));
        printf("MASK2(4,1) = 0x%08lx\n", MASK2(4,1));
        printf("MASK2(4,2) = 0x%08lx\n", MASK2(4,2));
        printf("MASK2(4,3) = 0x%08lx\n", MASK2(4,3));
        printf("MASK2(4,4) = 0x%08lx\n", MASK2(4,4));
    }
    if (1) {
        get_Cortex_L1_Insn();
        if (0) get_Cortex_L1_Insn_Matrix();  // old slow
    }
    if (1) {
        get_Cortex_L1_Tag();
        if (0) get_Cortex_L1_Tag_Matrix();  // old slow
    }
    return 0;
}
