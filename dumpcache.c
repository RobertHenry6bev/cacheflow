#include <asm/current.h>
#include <asm/io.h>
#include <asm/page.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pfn.h>
#include <linux/proc_fs.h>
#include <linux/rmap.h>
#include <linux/seq_file.h>
#include <linux/smp.h>
#include <linux/rmap.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/types.h>
#include <linux/version.h>

#include "params_kernel.h"

//
// TODO(robhenry): these are probably specific to reading the L2 Tag
//
#define CACHESETS_TO_WRITE 2048
#define L2_SIZE 2*1024*1024
#define MODNAME "dumpcache"
#define WAYS 16

#define FULL_ADDRESS 0

#pragma GCC push_options
#pragma GCC optimize ("O0")

// Might need this
//pragma GCC pop_options

/* Global variables */

/*
 * Unfortunately this (which? -rrh) platform has two apertures for DRAM, with a
 * large hole in the middle. Here is what the address space looks like
 * when the kernel is booted with mem=2560 (2.5 GB).
 *
 * block 1: 2.1Gbyte
 * 0x080000000 -> 0x0fedfffff:   Normal memory (aperture 1)
 * 0x0fee00000 -> 0x0ffffffff:   Cache buffer, part 1, size = 0x01200000 (aperture 1)
 *
 * block 2: 2.1Gbyte
 * 0x100000000 -> 0x1211fffff:   Normal memory (aperture 2)
 * 0x121200000 -> 0x17fffffff:   Cache buffer, part 2, size = 0x5ee00000 (aperture 2)
 */

#define CACHE_BUF_BASE1 0x0fee00000UL
#define CACHE_BUF_END1  0x0fee00000UL
//#define CACHE_BUF_END1 0x100000000UL

//
// This is an inelegant way to make kernel args include mem=3968M (per Renato)
// kernel 5.4 ubuntu 18.04: Edit files:
//    /boot/firmware/btcmd.txt
//    /boot/firmware/nobtcmd.txt
// kernel 5.13.0 ubuntu 21.10: Edit files:
//    /boot/firmware/cmdline.txt
//

#define CACHE_BUF_BASE2 (0xfaffffffUL+1)  //
#define CACHE_BUF_END2  (0xfbffffffUL+1)  //

#define CACHE_BUF_SIZE1 (CACHE_BUF_END1 - CACHE_BUF_BASE1)
#define CACHE_BUF_SIZE2 (CACHE_BUF_END2 - CACHE_BUF_BASE2)

#define CACHE_BUF_COUNT1 (CACHE_BUF_SIZE1 / sizeof(struct cache_sample))
#define CACHE_BUF_COUNT2 (CACHE_BUF_SIZE2 / sizeof(struct cache_sample))

/*
 * This variable is to keep track of the current buffer in use by the
 * module. It must be reset explicitly to prevent overwriting existing
 * data.
 */

static uint32_t cur_buf = 0;
static unsigned long flags;

/* Beginning of cache buffer in aperture 1 */
static struct cache_sample * __buf_start1 = NULL;

/* Beginning of cache buffer in aperture 2 */
static struct cache_sample * __buf_start2 = NULL;

/* Pointer to buffer currently in use. */
static struct cache_sample * cur_sample = NULL;

//static struct vm_area_struct *cache_set_buf_vma;
static int dump_all_indices_done;

//spinlock_t snap_lock = SPIN_LOCK_UNLOCK;
static DEFINE_SPINLOCK(snap_lock);

static bool rmap_one_func(struct page *page, struct vm_area_struct *vma, unsigned long addr, void *arg);
static void (*rmap_walk_func) (struct page *page, struct rmap_walk_control *rwc) = NULL;

/* Function prototypes */
static int dumpcache_open (struct inode *inode, struct file *filp);
static int dump_index(int index, struct cache_set* buf);
static int dump_all_indices(void);

static int get_Cortex_L1_Insn(void);
static int get_Cortex_L1_Tag(void);
static int get_Cortex_L1_Insn_Matrix(void);
static int get_Cortex_L1_Tag_Matrix(void);

static void *c_start(struct seq_file *m, loff_t *pos)
{
	return *pos < 1 ? (void *)1 : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v) {}

void cpu_stall (void * info)
{
	(void)info;
	spin_lock(&snap_lock);
	spin_unlock(&snap_lock);
}

static int c_show(struct seq_file *m, void *v)
{

	/* Make sure that the buffer has the right size */
	m->size = sizeof(struct cache_sample) + 32;
	m->buf = kvmalloc(sizeof(struct cache_sample) + 32, GFP_KERNEL);;

	/* Read buffer into sequential file interface */
	if (seq_write(m, cur_sample, sizeof(struct cache_sample)) != 0) {
		pr_info("Seq write returned non-zero value\n");
	}

	return 0;
}

/* This function returns a pointer to the ind-th sample in the
 * buffer. */
static inline struct cache_sample * sample_from_index(uint32_t ind)
{
	if (ind < CACHE_BUF_COUNT1) {
		return &__buf_start1[ind];
        } else if (ind < CACHE_BUF_COUNT1 + CACHE_BUF_COUNT2) {
		return &__buf_start2[ind - CACHE_BUF_COUNT1];
	} else {
		return NULL;
        }
}

static int acquire_snapshot(void)
{
	int processor_id;
	struct cpumask cpu_mask;

	/* Prepare cpu mask with all CPUs except current one */
	processor_id = get_cpu();
        // printk(KERN_INFO "acquire_snapshot processor_id=%d\n", processor_id);

	cpumask_copy(&cpu_mask, cpu_online_mask);
	cpumask_clear_cpu(processor_id, &cpu_mask); //processor_id, &cpu_mask);

	/* Acquire lock to spin other CPUs */
	spin_lock(&snap_lock);
	preempt_disable();

	/* Critical section! */
	on_each_cpu_mask(&cpu_mask, cpu_stall, NULL, 0);

	/* Perform cache snapshot */
        if (1) {
          get_Cortex_L1_Tag();
          if (0) get_Cortex_L1_Tag_Matrix();  // old slow
        } else if (0) {
          get_Cortex_L1_Insn();
          if (0) get_Cortex_L1_Insn_Matrix();  // old slow
        } else {
          dump_all_indices();
        }

	preempt_enable();
	spin_unlock(&snap_lock);
	put_cpu();

	/* Figure out if we need to increase the buffer pointer */
	if (flags & DUMPCACHE_CMD_AUTOINC_EN_SHIFT) {
		cur_buf += 1;

		if (cur_buf >= CACHE_BUF_COUNT1 + CACHE_BUF_COUNT2) {
			cur_buf = 0;
		}

		/* Set the pointer to the next available buffer */
		cur_sample = sample_from_index(cur_buf);
	}

	return 0;
}

static int dumpcache_config(unsigned long cmd)
{
	/* Set the sample buffer according to what was passed from user
	 * space */
	if(cmd & DUMPCACHE_CMD_SETBUF_SHIFT) {
		uint32_t val = DUMPCACHE_CMD_VALUE(cmd);

		if (val >= CACHE_BUF_COUNT1 + CACHE_BUF_COUNT2) {
			return -ENOMEM;
                }

		cur_buf = val;
		cur_sample = sample_from_index(val);
	}

	if (cmd & DUMPCACHE_CMD_GETBUF_SHIFT) {
		return cur_buf;
	}

	if (cmd & DUMPCACHE_CMD_AUTOINC_EN_SHIFT) {
		flags |= DUMPCACHE_CMD_AUTOINC_EN_SHIFT;
	} else if (cmd & DUMPCACHE_CMD_AUTOINC_DIS_SHIFT) {
		flags &= ~DUMPCACHE_CMD_AUTOINC_EN_SHIFT;
	}

	if (cmd & DUMPCACHE_CMD_RESOLVE_EN_SHIFT) {
		flags |= DUMPCACHE_CMD_RESOLVE_EN_SHIFT;
	} else if (cmd & DUMPCACHE_CMD_RESOLVE_DIS_SHIFT) {
		flags &= ~DUMPCACHE_CMD_RESOLVE_EN_SHIFT;
	}

	return 0;
}

/* The IOCTL interface of the proc file descriptor is used to pass
 * configuration commands */
static long dumpcache_ioctl(struct file *file, unsigned int ioctl, unsigned long arg)
{
	long err;
        printk(KERN_INFO "dumpcache_ioctl ioctl=%d arg=%ld\n", ioctl, arg);

	switch (ioctl) {
	case DUMPCACHE_CMD_CONFIG:
		err = dumpcache_config(arg);
		break;

	case DUMPCACHE_CMD_SNAPSHOT:
		err = acquire_snapshot();
		break;

	default:
		pr_err("Invalid command: 0x%08x\n", ioctl);
		err = -EINVAL;
		break;
	}

	return err;
}


static const struct seq_operations dumpcache_seq_ops = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= c_show
};

/* ProcFS entry setup and definitions  */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops dumpcache_ops = {
	// .owner = THIS_MODULE,
	// .proc_unlocked_ioctl = dumpcache_ioctl,
	.proc_compat_ioctl   = dumpcache_ioctl,
	.proc_open    = dumpcache_open,
	.proc_read    = seq_read,
	.proc_lseek	 = seq_lseek,
	.proc_release = seq_release
};
#else
static const struct file_operations dumpcache_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = dumpcache_ioctl,
	.compat_ioctl = dumpcache_ioctl,
	.open    = dumpcache_open,
	.read    = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release
};
#endif

//
// Raspberry Pi 4B has ARM Cortex-A72 in it
// See ARM Cortex-A57 MPCore Processor Revision: r1p3
//

//
// RAMINDEX operation.
//
// 4.3.64 in ARM Cortex-A57 MPCore Processor Technical Reference Manual
// 4.3.64 in ARM Cortex-A72 MPCore Processor Technical Reference Manual
//
// Purpose: Read the instruction side L1 array contents into the IL1DATAn
// register or read the data side L1 or L2 array contents into the
// DL1DATAn register.
//
static inline void __attribute__((always_inline)) asm_ramindex_msr(const char *whence, u32 ramindex)
{
        (void)whence;
	asm volatile(
	    "sys #0, c15, c4, #0, %0\n"
	    "dsb sy\n"  //        data sync barrier
	    "isb\n"     // instruction sync barrier
	    :: "r" (ramindex));
}

//
// reading from DL1DATA0_EL1
//
// 4.3.63 in ARM Cortex-A57 MPCore Processor Technical Reference Manual
// 4.3.63 in ARM Cortex-A72 MPCore Processor Technical Reference Manual
//
// This moves the 32-bit Data L1 Data n Register, EL1 to *dl1data
//
// The magic is in the S3_0_c15_c1_0 argument to the mrs instruction
// mrs == Move to Register from a System register.
//
static inline void  __attribute__((always_inline)) asm_ramindex_data_mrs(u32 *dl1data, u8 sel)
{
	if (sel & 0x01) {
	  asm volatile("mrs %0, S3_0_c15_c1_0" : "=r"(dl1data[0]));
	}
	if (sel & 0x02) {
	  asm volatile("mrs %0, S3_0_c15_c1_1" : "=r"(dl1data[1]));
	}
	if (sel & 0x04) {
	  asm volatile("mrs %0, S3_0_c15_c1_2" : "=r"(dl1data[2]));
	}
	if (sel & 0x08) {
	  asm volatile("mrs %0, S3_0_c15_c1_3" : "=r"(dl1data[3]));
	}
}

static inline void __attribute__((always_inline)) asm_ramindex_insn_mrs(u32 *ildata, u8 sel)
{
	if (sel & 0x01) {
	  asm volatile("mrs %0, S3_0_c15_c0_0" : "=r"(ildata[0]));
	}
	if (sel & 0x02) {
	  asm volatile("mrs %0, S3_0_c15_c0_1" : "=r"(ildata[1]));
	}
	if (sel & 0x04) {
	  asm volatile("mrs %0, S3_0_c15_c0_2" : "=r"(ildata[2]));
	}
	if (sel & 0x08) {
	  asm volatile("mrs %0, S3_0_c15_c0_3" : "=r"(ildata[3]));
	}
}

#define DO_GET
#include "cache_operations.c"

bool rmap_one_func(struct page *page, struct vm_area_struct *vma, unsigned long addr, void *arg)
{

	struct mm_struct* mm;
	struct task_struct* ts;
	struct process_data
	{
		pid_t pid;
		uint64_t addr;
	};

	((struct process_data*) arg)->addr = 0;

	// Check if mm struct is null
	mm = vma->vm_mm;
	if (!mm) {
		((struct process_data*) arg)->pid = (pid_t)99999;
		return true;
	}

	// Check if task struct is null
	ts = mm->owner;
	if (!ts) {
		((struct process_data*) arg)->pid = (pid_t)99999;
		return true;
	}

	// If pid is 1, continue searching pages
	if ((ts->pid) == 1) {
		((struct process_data*) arg)->pid = (ts->pid);
		return true;
	}

	// *Probably* the correct pid
	((struct process_data*) arg)->pid = (ts->pid);
	((struct process_data*) arg)->addr = addr;
	return false;
}

int done_func(struct page *page)
{
	return 1;
}


bool invalid_func(struct vm_area_struct *vma, void *arg)
{
	struct process_data
	{
		pid_t pid;
		uint64_t addr;
	};

	((struct process_data*) arg)->pid = (pid_t)99999;
	return false;
}

static int __dump_index_resolve(int index, struct cache_set* buf)
{
	int way;
	u32 physical_address;
	struct page* derived_page;
	struct rmap_walk_control rwc;
	struct rmap_walk_control * rwc_p;

	/* This will be used to invoke address resolution */
	struct cache_line process_data_struct;

	// Instantiate rmap walk control struct
	rwc.arg = &process_data_struct;
	rwc.rmap_one = rmap_one_func;
	rwc.done = NULL; //done_func;
	rwc.anon_lock = NULL;
	rwc.invalid_vma = invalid_func;
	rwc_p = &rwc;

	for (way = 0; way < WAYS; way++) {
		get_L2_tag(way, index, &physical_address);
		if (!physical_address) {
			continue;
                }

		derived_page = phys_to_page(((u64)physical_address << 1));

		// Initalize struct
		(buf->cachelines[way]).pid = 0;
		(buf->cachelines[way]).addr = ((u64)physical_address << 1);

		/* Reset address */
		process_data_struct.addr = 0;

	        // This call populates the struct in rwc struct
		if (rmap_walk_func) {
                    rmap_walk_func(derived_page, rwc_p);
                }

		// Fill cacheline struct with values obtained
                // from rmap_walk_func
		(buf->cachelines[way]).pid = process_data_struct.pid;
		if(process_data_struct.addr != 0) {
#if FULL_ADDRESS == 0
			(buf->cachelines[way]).addr = process_data_struct.addr;
#else
			(buf->cachelines[way]).addr = process_data_struct.addr | (((u64)physical_address << 1) & 0xfff);
#endif
		}
	}

	return 0;
}

static int __dump_index_noresolve(int index, struct cache_set* buf)
{
	int way;
	u32 physical_address;
	// printk(KERN_INFO "__dump_index_noresolve %d %p\n", index, buf);

	for (way = 0; way < WAYS; way++) {
		get_L2_tag(way, index, &physical_address);
		if (!physical_address) {
			continue;
                }

		// Initalize struct
		(buf->cachelines[way]).pid = 0; //process_data_struct->pid;// = 0;
		(buf->cachelines[way]).addr = ((u64)physical_address); //process_data_struct->addr;// = 0;

	}

	return 0;
}

#define L1IDATA_WAYS 3
static int __dump_L1Iinsn(int index, struct cache_set* buf)
{
  int way;
  u32 instructions[2];
  instructions[0] = 0;
  instructions[1] = 0;
  for (way = 0; way < L1IDATA_WAYS; way++) {
      buf->cachelines[way].pid = 777777;
      buf->cachelines[way].addr = 0x7777777777777777ULL;
      get_L1Iinsn(way, index, instructions);
      if (instructions[0] == 0) {  // TODO(robhenry):is 0 a legit insn?
          continue;
      }
      buf->cachelines[way].pid = 666666;
      buf->cachelines[way].addr =  // we're reusing the field name
        (((u64)instructions[0]) << 32) |
        (((u64)instructions[1]) <<  0) ;
  }

  return 0;
}

/* Invoke a smaller-footprint function in case address resolution has
 * not been requested */
static int dump_index(int index, struct cache_set* buf)
{
        if (1) {
          return __dump_L1Iinsn(index, buf);
        } else {
          // printk(KERN_INFO "dump_index %d %p\n", index, buf);
          if (flags & DUMPCACHE_CMD_RESOLVE_EN_SHIFT) {
                  return __dump_index_resolve(index, buf);
          } else {
                  return __dump_index_noresolve(index, buf);
          }
      }
}

static int dump_all_indices(void) {
	int i = 0;
	for (i = 0; i < CACHESETS_TO_WRITE; i++) {
		if (dump_index(i, &cur_sample->sets[i]) == 1){
			printk(KERN_INFO "Error dumping index: %d", i);
			return 1;
		}
	}
	return 0;
}

/* ProcFS interface definition */
static int dumpcache_open(struct inode *inode, struct file *filp)
{
	int ret;
	printk(KERN_INFO "dumpcache_open\n");

	if (!cur_sample) {
		pr_err("Something went horribly wrong. Invalid buffer.\n");
		return -EBADFD;
	}

	ret = seq_open(filp, &dumpcache_seq_ops);
	return ret;
}

int init_module(void)
{
	printk(KERN_INFO "dumpcache module is loaded cache_line.size=%ld cache_set.size=%ld cache_sample.size=%ld\n",
          sizeof(struct cache_line),
          sizeof(struct cache_set),
          sizeof(struct cache_sample)
          );
	printk(KERN_INFO "CACHE_BUF_SIZE1=%ld CACHE_BUF_SIZE2=%ld CACHE_BUF_COUNT1=%ld CACHE_BUF_COUNT2=%ld\n",
          CACHE_BUF_SIZE1,
          CACHE_BUF_SIZE2,
          CACHE_BUF_COUNT1,
          CACHE_BUF_COUNT2);

	dump_all_indices_done = 0;

	pr_info("Initializing SHUTTER. Entries: Aperture1 count = %ld, Aperture2 count = %ld\n",
	       CACHE_BUF_COUNT1, CACHE_BUF_COUNT2);

	/* Resolve the rmap_walk_func required to resolve physical
	 * address to virtual addresses */
        // rmap_walk_func = rmap_walk_locked;  // defined in include/linux/rmap.h
	if (!rmap_walk_func) {
		/* Attempt to find symbol */
		preempt_disable();
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)
		mutex_lock(&module_mutex);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
		rmap_walk_func = (void*) kallsyms_lookup_name("rmap_walk_locked");
#else
		rmap_walk_func = 0;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)
		mutex_unlock(&module_mutex);
#endif
		preempt_enable();

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
		/* Have we found a valid symbol? */
		if (!rmap_walk_func) {
			pr_err("Unable to find rmap_walk symbol. Aborting.\n");
			return -ENOSYS;
		}
#endif
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
  #define dumpcache_ioremap ioremap_nocache
#else
  #define dumpcache_ioremap ioremap_cache // despite the name, it apparently does no caching
#endif

	/* Map buffer apertures to be accessible from kernel mode */
        if (CACHE_BUF_SIZE1 > 0) {
          __buf_start1 = (struct cache_sample *) dumpcache_ioremap(CACHE_BUF_BASE1, CACHE_BUF_SIZE1);
          pr_info("__buf_start1 = 0x%p from 0x%016lx for %ld\n", __buf_start1, CACHE_BUF_BASE1, CACHE_BUF_COUNT1);
        } else {
          __buf_start1 = (struct cache_sample *) 0;
        }
        if (CACHE_BUF_SIZE2 > 0) {
#if 1
          __buf_start2 = (struct cache_sample *) dumpcache_ioremap(CACHE_BUF_BASE2, CACHE_BUF_SIZE2);
#else
          __buf_start2 = (struct cache_sample *) memremap(CACHE_BUF_BASE2, CACHE_BUF_SIZE2, MEMREMAP_WB);
#endif

          pr_info("__buf_start2 = 0x%p from 0x%016lx for %ld\n", __buf_start2, CACHE_BUF_BASE2, CACHE_BUF_COUNT2);
        } else {
          __buf_start2 = (struct cache_sample *) 0;
        }

        pr_info("buf_start1=%p buf_start2=%p\n", __buf_start1, __buf_start2);
	/* Check that we are all good! */
	if(/*!__buf_start1 ||*/ !__buf_start2) {
		pr_err("Unable to dumpcache_ioremap buffer space.\n");
		return -ENOMEM;
	}

	/* Set default flags, counter, and current sample buffer */
	flags = 0;
	cur_buf = 0;
	cur_sample = sample_from_index(0);

	/* Setup proc interface */
	proc_create(MODNAME, 0644, NULL, &dumpcache_ops);
        pr_info("load_module finished CCC\n");
	return 0;
}

void cleanup_module(void)
{
	printk(KERN_INFO "dumpcache module is unloaded\n");
	if (__buf_start1) {
		iounmap(__buf_start1);
		__buf_start1 = NULL;
	}

	if (__buf_start2) {
		iounmap(__buf_start2);
		__buf_start2 = NULL;
	}

	remove_proc_entry(MODNAME, NULL);
}

#pragma GCC pop_options
MODULE_LICENSE("GPL");
