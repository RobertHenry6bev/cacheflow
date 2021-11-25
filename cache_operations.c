//
// Get Tag of L2 cache entry at (index, way).
// Tag bank select ignored, 2MB L2 cache assumed.
//

#ifndef __KERNEL__
  #include  <assert.h>  // non-kernel only
#else
  #define assert(p)
#endif

#include "params_kernel.h"


//
// Returns a mask from inclusive bit ub to inclusive bit lb
//
#define MASK2(ub, lb) (((0x1UL<<((ub)-(lb)+1)) - 1) << lb)

#ifdef DO_GET

static inline void get_L2_tag(u32 way, u32 index, u32 *dl1data) {
	u32 ramid    = 0x10;  // L2 Tag RAM magic number (page 4-184)
	u32 ramindex = (ramid << 24) + (way << 18) + (index << 6);

	asm_ramindex_msr("getL2_tag", ramindex);
	asm_ramindex_data_mrs(dl1data, 0x01);  // reads just dl1data[0]

	// Check if MOESI state is invalid, and if so, zero out the address
	if (((*dl1data) & 0x03UL) == 0) {
          *dl1data = 0;
          return;
	}
	// Isolate the tag
	*dl1data &= ~(0x03UL);
	*dl1data <<= 12;
	*dl1data |= (index << 5);
}

static inline void  __attribute__((always_inline)) get_L1Itag(u32 way, u32 va, uint32_t *raw_values) {
  u32 ramindex = 0
    | (0x00 << 24)
    | ((way & 0x3) << 18)
    | ((va << 6) & MASK2(13, 6))
    ;
  // raw_values[0] = 0;
  // raw_values[1] = 0;
  asm_ramindex_msr("get_L1Itag", ramindex);
  asm_ramindex_insn_mrs(raw_values, 0x03);  // get raw_values[0] and raw_values[1]
}

static inline void  __attribute__((always_inline)) get_L1Iinsn(u32 way, u32 va, u32 *instructions)
{
  u32 ramindex = 0;
  assert((va & 0x7) == 0);
  ramindex = 0
    | (0x01 << 24)
    | ((way & 0x3) << 18)
    | va
    ;
  // instructions[0] = 0;
  // instructions[1] = 0;
  asm_ramindex_msr("get_L1Iinsn", ramindex);
  asm_ramindex_insn_mrs(instructions, 0x03);
}

//
// Slow way to access with multiple loops
// that ultimately should combine
// to make a simple incrementing virtual_address.
//
static int get_Cortex_L1_Insn_Matrix(void) {
    uint32_t way;
    union Cortex_L1_I_Insn_Cache_Union *cache =
        (union Cortex_L1_I_Insn_Cache_Union *)cur_sample;
    assert(sizeof(cache->struct_data) == sizeof(cache->vec_data));
    for (way = 0; way < 3; way++) {
        uint32_t set, pair;
        for (set = 0; set < 256; set++) {
            uint32_t va = (set << 6);
            struct Cortex_L1_I_Insn_Bank *p = &cache->struct_data.way[way].set[set];
            get_L1Itag(way, va, p->tag.raw); // gets 2 32-bit values
            for (pair = 0; pair < 4*2; pair++) {
                struct Cortex_L1_I_Insn_Pair *p =
                    &cache->struct_data.way[way].set[set].pair[pair];
                uint32_t va = (set << 6) | /*(bank << 4) |*/ (pair << 3);
                get_L1Iinsn(way, va, p->instruction);
            }
        }
    }
    return 0;
}

static int fill_Cortex_L1_Insn_Matrix(void) {
    uint32_t way;
    union Cortex_L1_I_Insn_Cache_Union *cache =
        (union Cortex_L1_I_Insn_Cache_Union *)cur_sample;
    assert(sizeof(cache->struct_data) == sizeof(cache->vec_data));
    for (way = 0; way < 3; way++) {
        uint32_t set;
        for (set = 0; set < 256; set++) {
            uint32_t va = (set << 6);
            struct Cortex_L1_I_Insn_Bank *p = &cache->struct_data.way[way].set[set];
            int valid = (p->tag.raw[1] >> 1) & 0x1;
            int ident = (p->tag.raw[1] >> 0) & 0x1;
            (void)ident;
            if (valid) {
                struct cache_line process_data_struct;
                //
                // The 2 bits in "common" need not be identical,
                // and that's observed empirically
                //
                // bits va[13:12] are lost.  They overlap the bottom 2 bits
                // of the phys address
                //
                uint64_t pa = p->tag.raw[0] << 12; // bits 43:12
                pa |= va & ((1 << 12) - 1);  // bits 11:6; 5:0 is 16 insns
                phys_to_pid(pa, &process_data_struct);
#if 1
                if (0 && process_data_struct.pid != 0) {
                    printk(KERN_INFO
                        "%d %3d va=0x%08x pa=0x%016llx pid=%d aka 0x%04x\n",
                        way, va>>6,
                        va, pa,
                        process_data_struct.pid,
                        process_data_struct.pid);
                }
#endif
                p->tag.pid = process_data_struct.pid;
            }
        }
    }
    return 0;
}

#endif  // DO_GET

#ifdef DO_PRINT  // {

void print_Cortex_L1_Insn(FILE *outfp,
      const struct Cortex_L1_I_Insn_Cache *cache) {
    uint32_t way, set, pair;
    for (way = 0; way < 3; way++) {
        for (set = 0; set < 256; set++) {
            const struct Cortex_L1_I_Insn_Bank *p = &cache->way[way].set[set];
            fprintf(outfp, "%d,%d,%d,0x%04x, 0x%08x,0x%08x ",
                way, set,
                p->tag.pid, p->tag.pid,
                p->tag.raw[1],
                p->tag.raw[0]);
            const char *sep = ",";
            for (pair = 0; pair < 4*2; pair++) {
                const struct Cortex_L1_I_Insn_Pair *p =
                   &cache->way[way].set[set].pair[pair];
                fprintf(outfp, "%s0x%08x,0x%08x",
                    sep,
                    p->instruction[0],
                    p->instruction[1]);
                sep = ",";
            }
            fprintf(outfp, "\n");
        }
    }
}

#endif  // DO_PRINT }
