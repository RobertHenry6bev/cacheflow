// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Copyright (c) 2021 Renato Mancuso et. al.
 */
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
#include <linux/seq_file.h>
#include <linux/smp.h>
#include <linux/rmap.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/types.h>
#include <linux/version.h>

#include "./params_kernel.h"

//
// TODO(robhenry): these are probably specific to reading the L2 Tag
//
#define CACHESETS_TO_WRITE 2048
#define L2_SIZE 2*1024*1024
#define MODNAME "dumpcache"
#define WAYS 16

#pragma GCC push_options
#pragma GCC optimize ("O1")  // NOLINT

#define TRACE_IOCTL if (0)

//
// Kernel >= 5.7 no longer seems to export some symbols
// to this out-of-tree module,
// even though this module is GPL'ed via the MODULE_LICENSE below.
// See https://lwn.net/Articles/813350/ (28Feb2020)
//
// See https://github.com/nbulischeck/tyton/blob/master/src/util.c
//
// robhenry never tried doing an in-tree build of this module to see
// if it then had visibility into non-exported symbols.
//

static bool rmap_one_func(
    struct page *page, struct vm_area_struct *vma,
    unsigned long addr, void *arg);
static void (*rmap_walk_locked_func)(
    struct page *page, struct rmap_walk_control *rwc) = NULL;
static unsigned long (*kallsyms_lookup_name_func)(
    const char *) = NULL;

static unsigned long lookup_name(const char *name) {
  unsigned long handle;
  if (kallsyms_lookup_name_func == NULL) {
    kallsyms_lookup_name_func = (unsigned long (*)(const char *))
      #include "kallsyms_lookup_name_func_addr.h.out"
    ;  /* */  // NOLINT
  }
  pr_info("kallsyms_lookup_name 0x%px %s\n",
      kallsyms_lookup_name_func, name);
  handle = kallsyms_lookup_name_func(name);
  pr_info("kallsyms_lookup_name 0x%px %s => 0x%016lx\n",
      kallsyms_lookup_name_func, name, handle);
  return handle;
}

//
// This is an inelegant way to make kernel args include mem=3968M (per Renato)
//
// kernel 5.4 ubuntu 18.04: Edit files:
//    /boot/firmware/btcmd.txt
//    /boot/firmware/nobtcmd.txt
//
// kernel 5.13.0 ubuntu 21.10: Edit files:
//    /boot/firmware/cmdline.txt
//

#define CACHE_BUF_BASE (0xfaffffffUL+1)  //
#define CACHE_BUF_END  (0xfbffffffUL+1)  //
#define CACHE_BUF_SIZE (CACHE_BUF_END - CACHE_BUF_BASE)
#define CACHE_BUF_COUNT (CACHE_BUF_SIZE / sizeof(union cache_sample))

/*
 * This variable is to keep track of the current buffer in use by the
 * module. It must be reset explicitly to prevent overwriting existing
 * data.
 */

static uint32_t cur_buf = 0;
static unsigned long flags;

/* Beginning of cache buffer in aperture 2 */
static union cache_sample * __buf_start = NULL;

/* Pointer to buffer currently in use. */
static union cache_sample * cur_sample = NULL;
static int dump_all_indices_done;
static DEFINE_SPINLOCK(snap_lock);

static int dumpcache_open(struct inode *inode, struct file *filep);

static int get_Cortex_L1_Insn(void);
static int fill_Cortex_L1_Insn(void);

static int get_Cortex_L2_Unif(void);
static int fill_Cortex_L2_Unif(void);

static void *c_start(struct seq_file *m, loff_t *pos) {
    return *pos < 1 ? (void *)1 : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos) {
    ++*pos;
    return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v) {}

void cpu_stall(void * info) {
    (void)info;
    spin_lock(&snap_lock);
    spin_unlock(&snap_lock);
}

static int c_show(struct seq_file *m, void *v) {
    /* Make sure that the buffer has the right size */
    m->size = sizeof(union cache_sample) + 32;
    m->buf = kvmalloc(sizeof(union cache_sample) + 32, GFP_KERNEL);;
    /* Read buffer into sequential file interface */
    if (seq_write(m, cur_sample, sizeof(union cache_sample)) != 0) {
            pr_info("Seq write returned non-zero value\n");
    }
    return 0;
}

/*
 * This function returns a pointer to the ind-th sample in the buffer.
 */
static inline union cache_sample * sample_from_index(uint32_t ind) {
    if (ind < CACHE_BUF_COUNT) {
        return &__buf_start[ind];
    } else {
        return NULL;
    }
}

static int acquire_snapshot(int observation) {
    int processor_id;
    struct cpumask cpu_mask;

    /* Prepare cpu mask with all CPUs except current one */
    processor_id = get_cpu();
    TRACE_IOCTL pr_info("acquire_snapshot processor_id=%d\n", processor_id);

    cpumask_copy(&cpu_mask, cpu_online_mask);
    cpumask_clear_cpu(processor_id, &cpu_mask);
    TRACE_IOCTL pr_info("acquire_snapshot cpu_mask=%*pbl\n",
        cpumask_pr_args(&cpu_mask));

    /* Acquire lock to spin other CPUs */
    spin_lock(&snap_lock);
    preempt_disable();

    /* Critical section! */
    on_each_cpu_mask(&cpu_mask, cpu_stall, NULL, 0);

    /* Perform cache snapshot */
    switch (observation) {
    case DUMPCACHE_DO_L1:
      // pr_info("DUMPCACHE_DO_L1");
      get_Cortex_L1_Insn();
      fill_Cortex_L1_Insn();
      break;

    case DUMPCACHE_DO_L2:
      // pr_info("DUMPCACHE_DO_L2");
      get_Cortex_L2_Unif();
      fill_Cortex_L2_Unif();
      break;

    default:
      // memset(cur_sample, 0, sizeof(*cur_sample));  // perhaps
      pr_info("Unknown observation %d", observation);
      break;
    }

    preempt_enable();
    spin_unlock(&snap_lock);
    put_cpu();

    /* Figure out if we need to increase the buffer pointer */
    if (flags & DUMPCACHE_CMD_AUTOINC_EN_SHIFT) {
            cur_buf += 1;

            if (cur_buf >= CACHE_BUF_COUNT) {
                    cur_buf = 0;
            }

            /* Set the pointer to the next available buffer */
            cur_sample = sample_from_index(cur_buf);
    }

    return 0;
}

static int dumpcache_config(unsigned long cmd) {
    /*
     * Set the sample buffer according to what was passed from user
     * space
     */
    if (cmd & DUMPCACHE_CMD_SETBUF_SHIFT) {
            uint32_t val = DUMPCACHE_CMD_VALUE(cmd);
            if (val >= CACHE_BUF_COUNT) {
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
static long dumpcache_ioctl(struct file *file,
        unsigned int ioctl, unsigned long arg) {
    long err;
    TRACE_IOCTL pr_info("dumpcache_ioctl ioctl=%d arg=%ld {\n", ioctl, arg);

    switch (ioctl) {
    case DUMPCACHE_CMD_CONFIG:
            err = dumpcache_config(arg);
            break;

    case DUMPCACHE_CMD_SNAPSHOT:
            err = acquire_snapshot(arg);
            break;

    default:
            pr_err("dumpcache_ioctl nvalid command: 0x%08x\n", ioctl);
            err = -EINVAL;
            break;
    }
    TRACE_IOCTL pr_info("dumpcache_ioctl ioctl=%d arg=%ld err=%ld }\n",
        ioctl, arg, err);

    return err;
}

static ssize_t dumpcache_seq_read(struct file *file,
    char __user *buf, size_t size, loff_t *ppos) {
  ssize_t ret;
  TRACE_IOCTL pr_info("dumpcache_seq_read size=%ld {", size);
  ret = seq_read(file, buf, size, ppos);
  TRACE_IOCTL pr_info("dumpcache_seq_read size=%ld ret=%ld }", size, ret);
  return ret;
}

static loff_t dumpcache_seq_lseek(struct file *file, loff_t off, int whence) {
  loff_t ret;
  TRACE_IOCTL pr_info("dumpcache_seq_lseek off=%lld whence=%d {",
      off, whence);
  ret = seq_lseek(file, off, whence);
  TRACE_IOCTL pr_info("dumpcache_seq_lseek off=%lld whence=%d =>ret=%lld }",
      off, whence, ret);
  return ret;
}

static int dumpcache_seq_release(struct inode *inode, struct file *file) {
  int ret;
  TRACE_IOCTL pr_info("dumpcache_seq_release {");
  ret = seq_release(inode, file);
  TRACE_IOCTL pr_info("dumpcache_seq_release ret=%d}", ret);
  return ret;
}

static const struct seq_operations dumpcache_seq_ops = {
    .start = c_start,
    .next = c_next,
    .stop = c_stop,
    .show = c_show
};

/* ProcFS entry setup and definitions  */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)  // {  // NOLINT

static const struct proc_ops dumpcache_ops = {
    .proc_ioctl = dumpcache_ioctl,
    .proc_compat_ioctl   = dumpcache_ioctl,
    .proc_open    = dumpcache_open,
    .proc_read    = dumpcache_seq_read,
    .proc_lseek   = dumpcache_seq_lseek,
    .proc_release = dumpcache_seq_release
};

#else  // } {

static const struct file_operations dumpcache_ops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = dumpcache_ioctl,
    .compat_ioctl = dumpcache_ioctl,
    .open    = dumpcache_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = seq_release
};

#endif  // }

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
static inline void __attribute__((always_inline))
asm_ramindex_msr(const char *whence, u32 ramindex) {
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
static inline void __attribute__((always_inline))
asm_ramindex_data_mrs(u32 *dl1data, u8 sel) {
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

static inline void __attribute__((always_inline))
asm_ramindex_insn_mrs(u32 *ildata, u8 sel) {
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

bool rmap_one_func(struct page *page,
      struct vm_area_struct *vma, unsigned long addr, void *v_arg) {
    struct mm_struct* mm;
    struct task_struct* ts;
    struct phys_to_pid_data *arg = (struct phys_to_pid_data *)v_arg;
    arg->addr = 0;
    mm = vma->vm_mm;
    if (!mm) {
        arg->pid = (pid_t)99999;
        return true;
    }

    // Check if task struct is null
    ts = mm->owner;
    if (!ts) {
        arg->pid = (pid_t)99998;
        return true;
    }

    pr_info("phys_to_pid survived to end addr=0x%016lx\n", addr);
    // If pid is 1, continue searching pages  (TODO(robhenry): Why?)
    if (ts->pid == 1) {
        arg->pid = ts->pid;
        return true;
    }

    // *Probably* the correct pid
    arg->pid = ts->pid;
    arg->addr = addr;
    return false;
}

int done_func(struct page *page) {
    return 1;
}

bool invalid_func(struct vm_area_struct *vma, void *arg) {
    struct process_data {
        pid_t pid;
        uint64_t addr;
    };

    ((struct process_data*) arg)->pid = (pid_t)99999;
    return false;
}

void phys_to_pid(u64 pa, struct phys_to_pid_data *pidinfo) {
    struct page *derived_page;
    struct rmap_walk_control rwc;

    static int all_count = 0;
    static int buf_count = 0;

    pidinfo->pid = 0;
    pidinfo->addr = 0;

    rwc.arg = pidinfo;
    rwc.rmap_one = rmap_one_func;
    rwc.done = NULL;  // perhaps use done_func?
    rwc.anon_lock = NULL;
    rwc.invalid_vma = invalid_func;

    //
    // Trip wire for counting the number of address translations
    // that fall within the hardware buffer.
    // This happened when I was using _WB semantics to the I/O memory, not _WT
    //
    all_count += 1;
    if ((all_count % 10000) == 0) {
      TRACE_IOCTL pr_info(
        "phys_to_page all_count=%9d buf_count=%9d or ~%02d%%\n",
        all_count, buf_count, (100 * buf_count)/all_count);
    }
    if (CACHE_BUF_BASE <= pa && pa < CACHE_BUF_END) {
      buf_count += 1;
      pidinfo->addr = pa;  // perhaps
      pidinfo->pid = -1;
      return;
    }
    if (rmap_walk_locked_func) {
      derived_page = phys_to_page(pa);
      // TRACE_IOCTL
      pr_info("rmap_walk_locked_func from addr 0x%016llx derived_page 0x%px\n",
          pa, derived_page);
      //
      // Kernel docs in source/mm/rmap.c says for rmap_walk_locked:
      //   ... Like rmap_walk,but caller holds relevant rmap lock ...
      // TODO(robhenry): Do we? where is the lock?
      //
      rmap_walk_locked_func(derived_page, &rwc);
      // TRACE_IOCTL
      pr_info(
          "rmap_walk_locked_func on 0x%016llx returns pid=%d addr=0x%016llx\n",
          (u64)derived_page,
          pidinfo->pid, pidinfo->addr);
    }
}

#define DO_GET
#include "cache_operations.c"

/* ProcFS interface definition */
static int dumpcache_open(struct inode *inode, struct file *filep) {
    int ret;
    TRACE_IOCTL pr_info("dumpcache_open {\n");

    if (!cur_sample) {
            pr_err("dumpcache_open: Something went wrong. Invalid buffer.\n");
            return -EBADFD;
    }

    ret = seq_open(filep, &dumpcache_seq_ops);
    TRACE_IOCTL pr_info("dumpcache_open ret=%d }\n", ret);
    return ret;
}

int init_module(void) {
    pr_info("CACHE_BUF_SIZE=0x%08lx CACHE_BUF_COUNT=0x%08lx\n",
        CACHE_BUF_SIZE, CACHE_BUF_COUNT);

    dump_all_indices_done = 0;

    pr_info("Initializing SHUTTER. Entries: Aperture2 count=%ld\n",
       CACHE_BUF_COUNT);

    /*
     * Resolve the rmap_walk_locked_func required to resolve physical addresses
     * to virtual addresses.
     */
    rmap_walk_locked_func = NULL;
    // rmap_walk_locked_func = rmap_walk_locked;  // include/linux/rmap.h
    rmap_walk_locked_func =
      (void (*)(struct page *, struct rmap_walk_control *))
      #include "rmap_walk_locked_func_addr.h.out"  // from /proc/kallsyms
    ;  // NOLINT
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)  // NOLINT
    rmap_walk_locked_func = NULL;
#endif
    if (!rmap_walk_locked_func) {
            /* Attempt to find symbol */
            preempt_disable();
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)  // NOLINT
            mutex_lock(&module_mutex);  // {
#endif
            rmap_walk_locked_func = (void*) lookup_name("rmap_walk_locked");
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)  // NOLINT
            mutex_unlock(&module_mutex);  // }
#endif
            preempt_enable();

            /* Have we found a valid symbol? */
            if (!rmap_walk_locked_func) {
                pr_err("Unable to find rmap_walk_locked symbol. Aborting.\n");
                return -ENOSYS;
            }
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)  // NOLINT
    #define dumpcache_ioremap ioremap_nocache
#else
    #define dumpcache_ioremap ioremap_cache  // doesn't really cache?! WTF?
#endif

    /*
     * Map buffer apertures to be accessible from kernel mode
     */
    if (CACHE_BUF_SIZE > 0) {
      //
      // See https://elixir.bootlin.com/linux/v5.11.22/source/include/linux/io.h#L151
      // See https://lwn.net/Articles/653585/
      // See https://www.kernel.org/doc/html/latest/driver-api/device-io.html
      // See https://elixir.bootlin.com/linux/v5.13.6/source/kernel/iomem.c#L44
      //
      __buf_start = (union cache_sample *) memremap(
          CACHE_BUF_BASE,
          CACHE_BUF_SIZE,
          MEMREMAP_WT);

      pr_info("__buf_start=0x%px from 0x%016lx for %ld\n",
          __buf_start, CACHE_BUF_BASE, CACHE_BUF_COUNT);
    } else {
      __buf_start = (union cache_sample *) 0;
    }
    pr_info("__buf_start=0x%px\n", __buf_start);

    if (!__buf_start) {
        pr_err("Unable to dumpcache_ioremap buffer space.\n");
        return -ENOMEM;
    }

    flags = 0;
    cur_buf = 0;
    cur_sample = sample_from_index(0);

    proc_create(MODNAME, 0644, NULL, &dumpcache_ops);
    pr_info("load_module finished\n");
    return 0;
}

void cleanup_module(void) {
    pr_info("dumpcache module is unloaded\n");
    if (__buf_start) {
            iounmap(__buf_start);
            __buf_start = NULL;
    }

    remove_proc_entry(MODNAME, NULL);
}

#pragma GCC pop_options

//
// See https://www.kernel.org/doc/html/latest/process/license-rules.html
//

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Renato Mancuso et. al.");
MODULE_DESCRIPTION("ARMv8 Cache Dumper using RAMINDEX.");
