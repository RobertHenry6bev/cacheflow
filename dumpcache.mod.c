#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xa1ea0080, "module_layout" },
	{ 0x2b1b5acd, "remove_proc_entry" },
	{ 0xedc03953, "iounmap" },
	{ 0x969a6562, "proc_create" },
	{ 0x4d924f20, "memremap" },
	{ 0x43b0c9c3, "preempt_schedule" },
	{ 0xa339e6e5, "on_each_cpu_cond_mask" },
	{ 0x5e3240a0, "__cpu_online_mask" },
	{ 0x7a2af7b4, "cpu_number" },
	{ 0x9688de8b, "memstart_addr" },
	{ 0x9f49dcc4, "__stack_chk_fail" },
	{ 0x460b609b, "seq_write" },
	{ 0x599fb41c, "kvmalloc_node" },
	{ 0x741150a6, "seq_open" },
	{ 0x45115c86, "seq_read" },
	{ 0xc9953998, "seq_lseek" },
	{ 0xe2b9bf8b, "seq_release" },
	{ 0x4829a47e, "memcpy" },
	{ 0x4c98d79b, "cpu_hwcap_keys" },
	{ 0x14b89635, "arm64_const_caps_ready" },
	{ 0xc5850110, "printk" },
	{ 0xb5b54b34, "_raw_spin_unlock" },
	{ 0xba8fbd64, "_raw_spin_lock" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "033FAE0C5B77503B063846F");
