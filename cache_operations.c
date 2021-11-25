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

#ifdef DO_GET  // {

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

static inline void  __attribute__((always_inline)) get_L2UData(u32 way, u32 pa, uint32_t *data)
{
  u32 ramindex = 0;
  assert((pa & 0xf) == 0);
  ramindex = 0
    | (0x011 << 24)
    | ((way & 0xf) << 18)
    | pa
    ;
  // data[0] = 0;
  // data[1] = 0;
  // data[2] = 0;
  // data[3] = 0;
  asm_ramindex_msr("get_L2UData", ramindex);
  asm_ramindex_data_mrs(data, 0x0f);  // request all 4 items
}

static int get_Cortex_L1_Insn(void) {
    uint32_t way;
    struct Cortex_L1_I_Insn_Cache *cache =
        (struct Cortex_L1_I_Insn_Cache *)cur_sample;
    for (way = 0; way < 3; way++) {
        uint32_t set, pair;
        for (set = 0; set < 256; set++) {
            uint32_t va = (set << 6);
            struct Cortex_L1_I_Insn_Bank *p = &cache->way[way].set[set];
            get_L1Itag(way, va, p->tag.raw); // gets 2 32-bit values
            for (pair = 0; pair < 4*2; pair++) {
                struct Cortex_L1_I_Insn_Pair *p =
                    &cache->way[way].set[set].pair[pair];
                uint32_t va = (set << 6) | /*(bank << 4) |*/ (pair << 3);
                get_L1Iinsn(way, va, p->instruction);
            }
        }
    }
    return 0;
}

static int fill_Cortex_L1_Insn(void) {
    uint32_t way;
    struct Cortex_L1_I_Insn_Cache *cache =
        (struct Cortex_L1_I_Insn_Cache *)cur_sample;
    for (way = 0; way < 3; way++) {
        uint32_t set;
        for (set = 0; set < 256; set++) {
            uint32_t va = (set << 6);
            struct Cortex_L1_I_Insn_Bank *p = &cache->way[way].set[set];
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
                if (0 && process_data_struct.pid != 0) {
                    printk(KERN_INFO
                        "%d %3d va=0x%08x pa=0x%016llx pid=%d aka 0x%04x\n",
                        way, va>>6,
                        va, pa,
                        process_data_struct.pid,
                        process_data_struct.pid);
                }
                p->tag.pid = process_data_struct.pid;
            }
        }
    }
    return 0;
}

static int get_Cortex_L2_Unif(void) {
    uint32_t way;
    struct Cortex_L2_Unif_Cache *cache =
        (struct Cortex_L2_Unif_Cache *)cur_sample;
    if (0) {
      printk(KERN_INFO "sizeof Cortex_l2_Unif_Cache=%ld\n",
          sizeof(struct Cortex_L2_Unif_Cache));
      printk(KERN_INFO "sizeof struct cache_sample=%ld\n",
          sizeof(struct cache_sample));
    }
    for (way = 0; way < Cortex_L2_NWAY; way++) {
        uint32_t set;
        for (set = 0; set < Cortex_L2_NROW; set++) {
            uint32_t pa = (set << 6);
            struct Cortex_L2_Unif_Bank *p = &cache->way[way].set[set];
            int quad;
            (void)pa;
            (void)p;
            // get_L2Itag(way, pa, p->tag.raw); // gets 2 32-bit values for tag
            for (quad = 0; quad < 4; quad++) {
                struct Cortex_L2_Unif_Quad *p =
                    &cache->way[way].set[set].quad[quad];
                uint32_t pa = (set << 6) | (quad << 4);
                get_L2UData(way, pa, p->instruction);
            }
        }
    }
    return 0;
}

static int fill_Cortex_L2_Unif(void) {
  // TODO(robhenry)
  return -1;
}

#endif  // DO_GET }

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

void print_Cortex_L2_Unif(FILE *outfp,
      const struct Cortex_L2_Unif_Cache *cache) {
    size_t L2_size =
        sizeof(struct Cortex_L2_Unif_Cache)
      - Cortex_L2_NWAY * Cortex_L2_NROW * sizeof(struct Cortex_L2_Unif_Tag);
    assert(L2_size == 1 * 1024 * 1024);  // true for Rasperry Pi4 BCM2711
    uint32_t way, set, quad;
    for (way = 0; way < Cortex_L2_NWAY; way++) {
        for (set = 0; set < Cortex_L2_NROW; set++) {
            const struct Cortex_L2_Unif_Bank *p = &cache->way[way].set[set];
            (void)p;
            fprintf(outfp, "%2d,%4d,  %d,0x%04x, 0x%08x,0x%08x ",
                way, set%1024,  // DO NOT COMMIT
                #if 1
                0, 0, 0, 0
                #else
                p->tag.pid, p->tag.pid,
                p->tag.raw[1],
                p->tag.raw[0]
                #endif
                );
            const char *sep = ",";
            for (quad = 0; quad < 4; quad++) {
                const struct Cortex_L2_Unif_Quad *p =
                   &cache->way[way].set[set].quad[quad];
                fprintf(outfp, "%s0x%08x,0x%08x,0x%08x,0x%08x",
                    sep,
                    p->instruction[0],
                    p->instruction[1],
                    p->instruction[2],
                    p->instruction[3]);
                sep = ",";
            }
            fprintf(outfp, "\n");
        }
    }
}

#endif  // DO_PRINT }
