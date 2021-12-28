#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

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
	{ 0x5ff65bdc, "module_layout" },
	{ 0x5e2d7875, "cpu_hwcap_keys" },
	{ 0x14b89635, "arm64_const_caps_ready" },
	{ 0x599fb41c, "kvmalloc_node" },
	{ 0x35702083, "remove_proc_entry" },
	{ 0xedc03953, "iounmap" },
	{ 0x27a34f1b, "proc_create" },
	{ 0xe7698027, "ioremap_cache" },
	{ 0x409bcb62, "mutex_unlock" },
	{ 0x2ab7989d, "mutex_lock" },
	{ 0xa9bc8b74, "module_mutex" },
	{ 0xb7f7328c, "seq_open" },
	{ 0x9688de8b, "memstart_addr" },
	{ 0xac997f61, "seq_release" },
	{ 0x28850f99, "seq_lseek" },
	{ 0x4fc539d6, "seq_read" },
	{ 0x9f49dcc4, "__stack_chk_fail" },
	{ 0x43b0c9c3, "preempt_schedule" },
	{ 0x25a65511, "on_each_cpu_mask" },
	{ 0x17de3d5, "nr_cpu_ids" },
	{ 0x5e3240a0, "__cpu_online_mask" },
	{ 0x7a2af7b4, "cpu_number" },
	{ 0xc5850110, "printk" },
	{ 0x319381db, "seq_write" },
	{ 0xb5b54b34, "_raw_spin_unlock" },
	{ 0xba8fbd64, "_raw_spin_lock" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "15B68B56035F0EEA4C14C96");
