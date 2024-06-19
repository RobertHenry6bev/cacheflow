/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2021 Renato Mancuso et. al.
 */

#ifndef PARAMS_KERNEL_H_
#define PARAMS_KERNEL_H_

#include <linux/types.h>

/* Command to access the configuration interface */
#define DUMPCACHE_CMD_CONFIG _IOW(0, 0, unsigned long)
/* Command to initiate a cache dump */
#define DUMPCACHE_CMD_SNAPSHOT _IOW(0, 1, unsigned long)

#define DUMPCACHE_CMD_VALUE_WIDTH  16
#define DUMPCACHE_CMD_VALUE_MASK   ((1 << DUMPCACHE_CMD_VALUE_WIDTH) - 1)
#define DUMPCACHE_CMD_VALUE(cmd)  (cmd & DUMPCACHE_CMD_VALUE_MASK)  // NOLINT

/* Command to set the current buffer number */
#define DUMPCACHE_CMD_SETBUF_SHIFT        (1 << (DUMPCACHE_CMD_VALUE_WIDTH + 1))

/* Command to retrieve the current buffer number */
#define DUMPCACHE_CMD_GETBUF_SHIFT        (1 << (DUMPCACHE_CMD_VALUE_WIDTH + 2))

/* Command to enable/disable buffer autoincrement */
#define DUMPCACHE_CMD_AUTOINC_EN_SHIFT    (1 << (DUMPCACHE_CMD_VALUE_WIDTH + 3))
#define DUMPCACHE_CMD_AUTOINC_DIS_SHIFT   (1 << (DUMPCACHE_CMD_VALUE_WIDTH + 4))

/* Command to enable/disable address resolution */
#define DUMPCACHE_CMD_RESOLVE_EN_SHIFT    (1 << (DUMPCACHE_CMD_VALUE_WIDTH + 5))
#define DUMPCACHE_CMD_RESOLVE_DIS_SHIFT   (1 << (DUMPCACHE_CMD_VALUE_WIDTH + 6))

/* Command to enable/disable snapshot timestamping */
#define DUMPCACHE_CMD_TIMESTAMP_EN_SHIFT  (1 << (DUMPCACHE_CMD_VALUE_WIDTH + 7))
#define DUMPCACHE_CMD_TIMESTAMP_DIS_SHIFT (1 << (DUMPCACHE_CMD_VALUE_WIDTH + 8))

enum DumpCacheWhichCache {
    DUMPCACHE_DO_L1 = 1,
    DUMPCACHE_DO_L2 = 2,
};

struct Cortex_L1_I_Tag {
  pid_t pid;
  uint64_t pa;    // constructed full physical address
  uint32_t raw[2];
};

struct Cortex_L1_I_Insn_Pair {
  uint32_t instruction[2];
};

struct Cortex_L1_I_Insn_Bank {
  struct Cortex_L1_I_Tag tag;
  struct Cortex_L1_I_Insn_Pair pair[8];
};

struct Cortex_L1_I_Insn_Way {
  struct Cortex_L1_I_Insn_Bank set[256];
};

struct Cortex_L1_I_Insn_Cache {
  struct Cortex_L1_I_Insn_Way way[3];
};

// -------------------
//
// This is for a 1Mbyte L2 cache,
// as found on a Raspberry Pi 4 ARM Cortex-A72 by Broadcom BCM2711
//
#define Cortex_L2_NROW 1024
#define Cortex_L2_NWAY   16

struct Cortex_L2_Unif_Tag {
  pid_t pid;
  uint8_t moesi;  // 2 bits only
  uint8_t id;     // non secure identifier for the physical address
  uint64_t pa_tag;
  uint64_t pa;    // constructed full physical address
  uint32_t raw[2];  // raw data from hardware
};

struct Cortex_L2_Unif_Quad {
  uint32_t instruction[4];
};

struct Cortex_L2_Unif_Bank {
  struct Cortex_L2_Unif_Tag tag;
  struct Cortex_L2_Unif_Quad quad[4];
};

struct Cortex_L2_Unif_Way {
  struct Cortex_L2_Unif_Bank set[Cortex_L2_NROW];
};

struct Cortex_L2_Unif_Cache {
    struct Cortex_L2_Unif_Way way[Cortex_L2_NWAY];
};

union cache_sample {
    struct Cortex_L1_I_Insn_Cache l1;
    struct Cortex_L2_Unif_Cache l2;
};

struct phys_to_pid_data {
    pid_t pid;
    uint64_t addr;
};

#endif  // PARAMS_KERNEL_H_
