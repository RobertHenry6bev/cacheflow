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

static inline void  __attribute__((always_inline)) get_L1Itag(u32 way, u32 va, uint32_t *instructions) {
  u32 ramindex = 0
    | (0x00 << 24)
    | ((way & 0x3) << 18)
    | ((va << 6) & MASK2(13, 6))
    ;
  // instructions[0] = 0;
  // instructions[1] = 0;
  asm_ramindex_msr("get_L1Itag", ramindex);
  asm_ramindex_insn_mrs(instructions, 0x03);  // get insn[0] and insn[1]
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

static int get_Cortex_L1_Tag_Matrix(void) {
    uint32_t way, set;
    union Cortex_L1_I_Tag_Cache_Union *cache =
        (union Cortex_L1_I_Tag_Cache_Union *)cur_sample;
    assert(sizeof(cache->struct_data) == sizeof(cache->vec_data));
    for (way = 0; way < 3; way++) {
        for (set = 0; set < 256; set++) {  // row & bank select
            struct Cortex_L1_I_Tag_Info *p =
              &cache->struct_data.way[way].set[set];
            uint32_t index = (set << 6);
            get_L1Itag(way, index, p->u.tag_pair.instruction);
        }
    }
    return 0;
}

//
// Read from the L1_Tag as quickly as possible.
// We'll go through the data later in fill_Cortex_L1_Tag
// and map physaddrs to pids.
//
static int get_Cortex_L1_Tag(void) {
    uint32_t way;
    union Cortex_L1_I_Tag_Cache_Union *cache =
        (union Cortex_L1_I_Tag_Cache_Union *)cur_sample;
    struct Cortex_L1_I_Tag_Pair *p =
        (struct Cortex_L1_I_Tag_Pair *)&cache->vec_data[0];
    assert(sizeof(cache->struct_data) == sizeof(cache->vec_data));
    for (way = 0; way < 3; way++) {
        uint32_t va;
        // (1<<14)/64 == 256 steps
        for (va = 0; va < (1<<14); va += 64) {
            get_L1Itag(way, va, p->instruction); // gets 2 32-bit "insns"[sic]
            p += 1;
        }
    }
    return 0;
}

static int fill_Cortex_L1_Tag(void) {
    uint32_t way;
    union Cortex_L1_I_Tag_Cache_Union *cache =
        (union Cortex_L1_I_Tag_Cache_Union *)cur_sample;
    struct Cortex_L1_I_Tag_Pair *p =
        (struct Cortex_L1_I_Tag_Pair *)&cache->vec_data[0];
    assert(sizeof(cache->struct_data) == sizeof(cache->vec_data));
    for (way = 0; way < 3; way++) {
        uint32_t va;
        // (1<<14)/64 == 256 steps
        for (va = 0; va < (1<<14); va += 64) {
            int valid = (p->instruction[1] >> 1) & 0x1;
            int ident = (p->instruction[1] >> 0) & 0x1;
            (void)ident;
            p->instruction[1] &= 0xffff;  // knock out upper 16 bits to hold pid
            if (valid) {
                struct cache_line process_data_struct;
                //
                // The 2 bits in "common" need not be identical,
                // and that's observed empirically
                //
                // bits va[13:12] are lost.  They overlap the bottom 2 bits
                // of the phys address
                //
                uint64_t pa = p->instruction[0] << 12; // bits 43:12
                pa |= va & ((1 << 12) - 1);  // bits 11:6; 5:0 is 16 insns
                phys_to_pid(pa, &process_data_struct);
                printk(KERN_INFO
                    "%d %3d va=0x%08x pa=0x%016llx pid=%d aka 0x%04x\n",
                    way, va>>6,
                    va, pa,
                    process_data_struct.pid,
                    process_data_struct.pid);
                p->instruction[1] |= (process_data_struct.pid << 16);
            }
            p += 1;
        }
    }
    return 0;
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
        uint32_t set, bank, pair;
        for (set = 0; set < 256; set++) {
            for (bank = 0; bank < 4; bank++) {
                for (pair = 0; pair < 2; pair++) {
                    struct Cortex_L1_I_Insn_Pair *p =
                        &cache->struct_data.way[way].set[set].bank[bank].pair[pair];
                    uint32_t va = (set << 6) | (bank << 4) | (pair << 3);
                    get_L1Iinsn(way, va, p->instruction);
              }
            }
        }
    }
    return 0;
}

static int get_Cortex_L1_Insn(void) {
    uint32_t way;
    union Cortex_L1_I_Insn_Cache_Union *cache =
        (union Cortex_L1_I_Insn_Cache_Union *)cur_sample;
    struct Cortex_L1_I_Insn_Pair *p =
        (struct Cortex_L1_I_Insn_Pair *)&cache->vec_data[0];
    assert(sizeof(cache->struct_data) == sizeof(cache->vec_data));
    for (way = 0; way < 3; way++) {
        uint32_t va;
        for (va = 0; va < (1<<14); va += 8) {
            get_L1Iinsn(way, va, p->instruction);
            p += 1;
        }
    }
    return 0;
}


#endif  // DO_GET

#ifdef DO_PRINT  // {

void print_Cortex_L1_Insn(FILE *outfp,
      const struct Cortex_L1_I_Insn_Cache *cache) {
    uint32_t way, set, bank, pair;
    for (way = 0; way < 3; way++) {
        for (set = 0; set < 256; set++) {
            fprintf(outfp, "%d,%d", way, set);
            const char *sep = ",";
            for (bank = 0; bank < 4; bank++) {
                for (pair = 0; pair < 2; pair++) {
                    const struct Cortex_L1_I_Insn_Pair *p =
                       &cache->way[way].set[set].bank[bank].pair[pair];
                    fprintf(outfp, "%s0x%08x,0x%08x",
                        sep, p->instruction[0], p->instruction[1]);
                    sep = ",";
                }
            }
            fprintf(outfp, "\n");
        }
    }
}

void print_Cortex_L1_Tag(FILE *outfp,
      const struct Cortex_L1_I_Tag_Cache *cache) {
    uint32_t way, set;
    const char *sep = "";
    for (way = 0; way < 3; way++) {
        for (set = 0; set < 256; set++) {
            const struct Cortex_L1_I_Tag_Info *p =
                &cache->way[way].set[set];
            fprintf(outfp, "%s%d,%d, 0x%08x,0x%08x\n",
                sep, way, set,
                p->u.d.meta,
                p->u.d.physical_address);
            sep = "";
        }
    }
}

#endif  // DO_PRINT }
