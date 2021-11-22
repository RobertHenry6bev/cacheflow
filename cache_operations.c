//
// Get Tag of L2 cache entry at (index, way).
// Tag bank select ignored, 2MB L2 cache assumed.
//

// #include  <assert.h>  // non-kernel only

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

static inline void get_L1Itag(u32 way, u32 index, uint32_t *instructions) {
  //
  // index is the virtual address. See figure 4-58
  //
  u32 ramid    = 0x00;  // L1-I Tag RAM
  u32 ramindex = 0
    | (ramid << 24)
    | ((way & 0x3) << 18)
    | ((index << 6) & MASK2(13, 6))
    ;
  instructions[0] = 0;
  instructions[1] = 0;
  asm_ramindex_msr("get_L1Itag", ramindex);
  asm_ramindex_insn_mrs(instructions, 0x03);  // get insn[0] and insn[1]
  // instructions[0] = 0xbadf00dUL;  // dummy physical address
  // instructions[1] = 0x1111111UL;  // dummy 2-bit field: valid and non-secure id
}

static inline void get_L1Iinsn(u32 way, u32 va, u32 *instructions)
{
  //
  // index is the virtual address. See figure 4-58
  //
  u32 ramid    = 0x01;  // L1-I Data RAM
  // assert((va & 0x7) == 0);
  u32 ramindex = 0
    | (ramid << 24)
    | ((way & 0x3) << 18)
    | va
    ;
  instructions[0] = 0;
  instructions[1] = 0;
  asm_ramindex_msr("get_L1Iinsn", ramindex);
  asm_ramindex_insn_mrs(instructions, 0x03);  // get insn[0] and insn[1]
}

static int get_Cortex_L1_Tag(void) {
    uint32_t way, bank, set;
    struct Cortex_L1_I_Tag_Cache *cache =
        (struct Cortex_L1_I_Tag_Cache *)cur_sample;
    for (way = 0; way < 3; way++) {
        for (bank = 0; bank < 2; bank++) {
            for (set = 0; set < 128; set++) {
                struct Cortex_L1_I_Tag_Bank_Line *p =
                  &cache->way[way].bank[bank].set[set];
                uint32_t index = (set << 7) | (bank << 6);
                get_L1Itag(way, index, p->u.instruction);
            }
        }
    }
    return 0;
}

static int get_Cortex_L1_Insn(void) {
    uint32_t way, bank, set, pair;
    struct Cortex_L1_I_Insn_Cache *cache =
        (struct Cortex_L1_I_Insn_Cache *)cur_sample;
    for (way = 0; way < 3; way++) {
        for (set = 0; set < 256; set++) {
            for (bank = 0; bank < 4; bank++) {
                for (pair = 0; pair < 2; pair++) {
                    struct Cortex_L1_I_Insn_Pair *p =
                        &cache->way[way].set[set].bank[bank].pair[pair];
                    uint32_t va = (set << 6) | (bank << 4) | (pair << 3);
#ifdef TEST_DEBUG
                        printf("way=%d set=%4d bank=%d pair=%d: va 0x%03x\n",
                            way, set, bank, pair, va);
#endif
                    get_L1Iinsn(way, va, p->instruction);
                }
            }
        }
    }
    return 0;
}

#endif  // DO_GET

#ifdef DO_PRINT
void print_Cortex_L1_Insn(FILE *outfp,
      const struct Cortex_L1_I_Insn_Cache *cache) {
    uint32_t way, bank, set, pair;
    for (way = 0; way < 3; way++) {
        for (set = 0; set < 256; set++) {
            for (bank = 0; bank < 4; bank++) {
                for (pair = 0; pair < 2; pair++) {
                    const struct Cortex_L1_I_Insn_Pair *p =
                       &cache->way[way].set[set].bank[bank].pair[pair];
                    fprintf(outfp, ",0x%08x,0x%08x",
                        p->instruction[0], p->instruction[1]);
                }
            }
            fprintf(outfp, "\n");
        }
    }
}

void print_Cortex_L1_Tag(FILE *outfp,
      const struct Cortex_L1_I_Tag_Cache *cache) {
    uint32_t way, bank, set;
    const char *sep = "";
    for (way = 0; way < 3; way++) {
        for (bank = 0; bank < 2; bank++) {
            for (set = 0; set < 128; set++) {
                const struct Cortex_L1_I_Tag_Bank_Line *p =
                  &cache->way[way].bank[bank].set[set];
                fprintf(outfp, "%s%d,%d,%d, 0x%08x, 0x%08x\n",
                  sep, way, bank, set,
                  p->u.d.meta, p->u.d.physical_address);
                sep = "";
            }
        }
    }
}

#endif  // DO_PRINT
