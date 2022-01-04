// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2021 Renato Mancuso et. al.
 */

#ifdef __KERNEL__
  static void our_assert(const char *file, int line, const char *predicate);
  #define assert(p) if (!(p)) our_assert(__FILE__, __LINE__, #p)
#else
  #include  <assert.h>  // non-kernel only
#endif

#include "./params_kernel.h"

//
// Return a mask from inclusive bit ub to inclusive bit lb
//
#define MASK2(ub, lb) (((0x1UL << ((ub)-(lb)+1)) - 1) << lb)

#ifdef DO_GET  // {

#define FILL 0xaaaaaaaaULL

static inline void  __attribute__((always_inline))
get_L1Itag(u32 way, u32 va, uint32_t *raw_values) {
  u32 ramindex = 0
    | (0x00 << 24)  // magic RAM number
    | ((way & 0x3) << 18)
    | ((va << 6) & MASK2(13, 6))
    ;  // NOLINT
  raw_values[0] = FILL;
  raw_values[1] = FILL;
  asm_ramindex_msr("get_L1Itag", ramindex);
  asm_ramindex_insn_mrs(raw_values, 0x03);  // gets raw_values[0], raw_values[1]
}

//
// Read L1-I Data RAM (the instructions themselves)
//
static inline void  __attribute__((always_inline))
get_L1Iinsn(u32 way, u32 va, u32 *instructions) {
  u32 ramindex = 0;
  assert((va & 0x7) == 0);
  ramindex = 0
    | (0x01 << 24)  // magic RAM number
    | ((way & 0x3) << 18)
    | va
    ;  // NOLINT
  instructions[0] = FILL;
  instructions[1] = FILL;
  asm_ramindex_msr("get_L1Iinsn", ramindex);
  asm_ramindex_insn_mrs(instructions, 0x03);
}

static inline void __attribute__((always_inline))
get_L2tag(u32 way, u32 set, struct Cortex_L2_Unif_Tag *p) {
    u32 ramindex = 0
      | (0x10 << 24)  // magic RAM number
      | ((way & 0xf) << 18)
      | ((set << 6) & MASK2(16, 6))
      ;  // NOLINT
    p->raw[0] = FILL;
    asm_ramindex_msr("getL2_tag", ramindex);
    asm_ramindex_data_mrs(p->raw, 0x01);  // reads just p->raw[0]
    p->pid = -1;
    p->moesi = p->raw[0] & 0x3;
    p->pa_tag = ((p->raw[0] & MASK2(30, 2)) >> 2) << 15;  // 43:15
    p->id = (p->raw[0] >> 31) & 0x1;
    switch (p->moesi) {
    case 0:  // invalid
       p->pa_tag = 0;
       break;
    case 1:  // exclusive or modified
    case 2:  // reserved
    case 3:  // shared or owned
      break;
    }
}

static inline void  __attribute__((always_inline))
get_L2UData(u32 way, u32 pa, uint32_t *data) {
  u32 ramindex = 0;
  assert((pa & 0xf) == 0);
  ramindex = 0
    | (0x011 << 24)  // magic RAM number
    | ((way & 0xf) << 18)
    | pa
    ;  // NOLINT
  data[0] = FILL;
  data[1] = FILL;
  data[2] = FILL;
  data[3] = FILL;
  asm_ramindex_msr("get_L2UData", ramindex);
  asm_ramindex_data_mrs(data, 0x0f);  // request all 4 items
}

//
// Read all L1 I cache as quickly as possible.
// We'll do address translation in fill_Cortex_L1_Insn(void).
//
static int get_Cortex_L1_Insn(void) {
    uint32_t way;
    struct Cortex_L1_I_Insn_Cache *cache =
        (struct Cortex_L1_I_Insn_Cache *)cur_sample;
    for (way = 0; way < 3; way++) {
        uint32_t set, pair;
        for (set = 0; set < 256; set++) {
            uint32_t va = (set << 6);
            struct Cortex_L1_I_Insn_Bank *p = &cache->way[way].set[set];
            get_L1Itag(way, va, p->tag.raw);  // gets 2 32-bit values
            for (pair = 0; pair < 4*2; pair++) {
                struct Cortex_L1_I_Insn_Pair *p =
                    &cache->way[way].set[set].pair[pair];
                uint32_t va = (set << 6) | (pair << 3);
                get_L1Iinsn(way, va, p->instruction);
            }
        }
    }
    return 0;
}

//
// Do address translation.  Call get_Cortex_L1_Insn first.
//
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
      if (p->pair[0].instruction[0] != 0x14000004) {
        p->tag.pid = 2;
        continue;
      }
      if (1) {
        pr_info("\nxxx valid=%d ident=%d @1=0x%08x @0=0x%08x\n",
          valid, ident, p->tag.raw[1], p->tag.raw[0]);
      }
      if (valid) {
        struct phys_to_pid_data pid_data;
        //
        // The 2 bits in "common" need not be identical,
        // and that's observed empirically
        //
        // bits va[13:12] are lost.
        // They overlap the bottom 2 bits of the phys address.
        //
        uint64_t pa_a = (p->tag.raw[0] << 12);   // bits 43:12
        uint64_t va_a = (va & MASK2(13, 0));
        uint64_t comm = MASK2(13, 12);
        int delta;
        (void)va_a;
        (void)comm;
        for (delta = 0; delta < 4; delta++) {
          uint64_t pa = (pa_a & MASK2(31, 14)) | (delta << 12) | (va & MASK2(11, 0));
          phys_to_pid("L1", pa, &pid_data);
          if (1 /*&& pid_data.pid != 0*/) {
            pr_info(
                "yyy %d %3d va=0x%08x pa=0x%016llx delta=%d pid=%d\n",
                way, va>>6,
                va, pa,
                delta,
                pid_data.pid);
          }
        }
        p->tag.pid = pid_data.pid;
      }
    }
  }
  return 0;
}

static int get_Cortex_L2_Unif(void) {
  uint32_t way;
  struct Cortex_L2_Unif_Cache *cache =
    (struct Cortex_L2_Unif_Cache *)cur_sample;
  for (way = 0; way < Cortex_L2_NWAY; way++) {
    uint32_t set;
    for (set = 0; set < Cortex_L2_NROW; set++) {
      int quad;
      struct Cortex_L2_Unif_Bank *p = &cache->way[way].set[set];
      get_L2tag(way, set, &p->tag);
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
    uint32_t way;
    struct Cortex_L2_Unif_Cache *cache =
        (struct Cortex_L2_Unif_Cache *)cur_sample;
    for (way = 0; way < Cortex_L2_NWAY; way++) {
        uint32_t set;
        for (set = 0; set < Cortex_L2_NROW; set++) {
            struct Cortex_L2_Unif_Tag *p = &cache->way[way].set[set].tag;
            if (p->pa_tag & MASK2(14, 0)) {
                pr_info("invalid p->pa_tag 0x%016llx\n", p->pa_tag);
            }
            //
            // half from 512..1023 'F'
            // p->pa = (p->pa_tag                ) | ((set<<6) & MASK2(14, 6));
            //
            // random half 'F'
            // p->pa = (p->pa_tag & ~MASK2(16, 0)) | ((set<<6) & MASK2(16, 6));
            //
            // empirically seems to be the best split.
            //
            p->pa = (p->pa_tag & ~MASK2(15, 0)) | ((set << 6) & MASK2(15, 6));

            if (cache->way[way].set[set].quad[0].instruction[0] != 0x14000004) {
                p->pid = 2;
                continue;
            }

            if (p->moesi != 0) {
                struct phys_to_pid_data pid_data;
                phys_to_pid("L2", p->pa, &pid_data);
                p->pid = pid_data.pid;
            }
        }
    }
    return 0;
}

static void our_assert(const char *file, int line, const char *predicate) {
  pr_info("ASSERT FAIL: %s:%d %s\n", file, line, predicate);
}

#endif  // DO_GET }

#ifdef DO_PRINT  // {

#include <set>  // This user code can only be compiled with g++

void print_Cortex_L1_Insn(FILE *outfp,
      const struct Cortex_L1_I_Insn_Cache *cache,
      std::set<pid_t> *pidset) {
    uint32_t way, set, pair;
    for (way = 0; way < 3; way++) {
        for (set = 0; set < 256; set++) {
            const struct Cortex_L1_I_Insn_Bank *p = &cache->way[way].set[set];
            pidset->insert(p->tag.pid);
            fprintf(outfp, "%d,%d,%d,0x%04x, 0x%08x,0x%08x ",
                way, set,
                p->tag.pid, p->tag.pid,
                p->tag.raw[1],   // bottom 2 bits: valid bit; non-secure id
                p->tag.raw[0]);  // physical address tag [43:12]
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
      const struct Cortex_L2_Unif_Cache *cache,
      std::set<pid_t> *pidset) {
    size_t L2_size =
        sizeof(struct Cortex_L2_Unif_Cache)
      - Cortex_L2_NWAY * Cortex_L2_NROW * sizeof(struct Cortex_L2_Unif_Tag);
    assert(L2_size == 1 * 1024 * 1024);  // true for Rasperry Pi4 Broadcom BCM2711
    uint32_t way, set, quad;
    for (way = 0; way < Cortex_L2_NWAY; way++) {
        for (set = 0; set < Cortex_L2_NROW; set++) {
            const struct Cortex_L2_Unif_Bank *p = &cache->way[way].set[set];
            pidset->insert(p->tag.pid);
            //
            // Check that the post conditions expected by e11_flood.c are met.
            // Check that pid determined by the kernel from the phys address
            // is identical to the pid embedded in the instruction stream.
            //
            // This only makes sense when looking for telltale
            // signaturres from e11_flood.c
            //
            int fail_brand = 0;
            int fail_pid = 0;
            if (0) {
              int q;
              for (q = 0; q < 4; q++) {
                fail_brand += (p->quad[q].instruction[0] != 0x14000004);
                fail_brand += (p->quad[q].instruction[1] != 0xffffffff);
                fail_pid +=   (
                    (pid_t)(p->quad[q].instruction[2]) != p->tag.pid);
              }
            }
            fprintf(outfp, "%c%c, %2d,%4d,%d,  %5d,0x%04x, 0x%08x,0x%016lx ",
                fail_brand ? 'B' : '-',
                fail_pid   ? 'P' : '-',
                way, set,
                p->tag.moesi,
                p->tag.pid, p->tag.pid,
                p->tag.raw[0],
                p->tag.pa);
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
