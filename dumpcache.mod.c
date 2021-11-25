#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(.gnu.linkonce.this_module) = {
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
__used __section(__versions) = {
	{ 0xfe9bc451, "module_layout" },
	{ 0x9bba1218, "seq_release" },
	{ 0x4ebdbc33, "seq_read" },
	{ 0x1d755966, "seq_lseek" },
	{ 0xc38127c9, "remove_proc_entry" },
	{ 0xedc03953, "iounmap" },
	{ 0xf1d4aad3, "proc_create" },
	{ 0x6b4b2933, "__ioremap" },
	{ 0x409bcb62, "mutex_unlock" },
	{ 0xe007de41, "kallsyms_lookup_name" },
	{ 0x2ab7989d, "mutex_lock" },
	{ 0xa9bc8b74, "module_mutex" },
	{ 0x220287d5, "seq_open" },
	{ 0x9688de8b, "memstart_addr" },
	{ 0xdecd0b29, "__stack_chk_fail" },
	{ 0x43b0c9c3, "preempt_schedule" },
	{ 0x8e116a88, "on_each_cpu_mask" },
	{ 0x921b07b1, "__cpu_online_mask" },
	{ 0x7a2af7b4, "cpu_number" },
	{ 0x8f678b07, "__stack_chk_guard" },
	{ 0xc5850110, "printk" },
	{ 0x3980227b, "seq_write" },
	{ 0x301fa007, "_raw_spin_unlock" },
	{ 0xdbf17652, "_raw_spin_lock" },
	{ 0x1fdc7df2, "_mcount" },
	{ 0x599fb41c, "kvmalloc_node" },
	{ 0x3d8560e4, "cpu_hwcaps" },
	{ 0xb2ead97c, "kimage_vaddr" },
	{ 0x4b50cb71, "cpu_hwcap_keys" },
	{ 0x14b89635, "arm64_const_caps_ready" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "52370AE8FE9A0D0C3895157");
