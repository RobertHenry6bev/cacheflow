#ifndef __CACHEFLOW_PARAMS_KERNEL_H
#define __CACHEFLOW_PARAMS_KERNEL_H

/* Command to access the configuration interface */
#define DUMPCACHE_CMD_CONFIG _IOW(0, 0, unsigned long)
/* Command to initiate a cache dump */
#define DUMPCACHE_CMD_SNAPSHOT _IOW(0, 1, unsigned long)

#define DUMPCACHE_CMD_VALUE_WIDTH  16
#define DUMPCACHE_CMD_VALUE_MASK   ((1 << DUMPCACHE_CMD_VALUE_WIDTH) - 1)
#define DUMPCACHE_CMD_VALUE(cmd)		\
	(cmd & DUMPCACHE_CMD_VALUE_MASK)

/* Command to set the current buffer number */
#define DUMPCACHE_CMD_SETBUF_SHIFT           (1 << (DUMPCACHE_CMD_VALUE_WIDTH + 1))

/* Command to retrievet the current buffer number */
#define DUMPCACHE_CMD_GETBUF_SHIFT           (1 << (DUMPCACHE_CMD_VALUE_WIDTH + 2))

/* Command to enable/disable buffer autoincrement */
#define DUMPCACHE_CMD_AUTOINC_EN_SHIFT       (1 << (DUMPCACHE_CMD_VALUE_WIDTH + 3))
#define DUMPCACHE_CMD_AUTOINC_DIS_SHIFT      (1 << (DUMPCACHE_CMD_VALUE_WIDTH + 4))

/* Command to enable/disable address resolution */
#define DUMPCACHE_CMD_RESOLVE_EN_SHIFT       (1 << (DUMPCACHE_CMD_VALUE_WIDTH + 5))
#define DUMPCACHE_CMD_RESOLVE_DIS_SHIFT      (1 << (DUMPCACHE_CMD_VALUE_WIDTH + 6))

/* Command to enable/disable snapshot timestamping */
#define DUMPCACHE_CMD_TIMESTAMP_EN_SHIFT       (1 << (DUMPCACHE_CMD_VALUE_WIDTH + 7))
#define DUMPCACHE_CMD_TIMESTAMP_DIS_SHIFT      (1 << (DUMPCACHE_CMD_VALUE_WIDTH + 8))

//
//TODO(robhenry); These are probably specific to the Cortex A72(?) L2 Tag
//
#define NUM_CACHESETS 2048
#define CACHESIZE 1024*1024*2
#define NUM_CACHELINES 16

/* Struct representing a single cache line */
struct cache_line {
	pid_t pid;
	uint64_t addr;
};

struct cache_set {
	struct cache_line cachelines[NUM_CACHELINES];
};

struct cache_sample {
	struct cache_set sets[NUM_CACHESETS];
};

#endif  // __CACHEFLOW_PARAMS_KERNEL_H
