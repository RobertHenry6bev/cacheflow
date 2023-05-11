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
	{ 0x176214b6, "module_layout" },
	{ 0x9daec360, "remove_proc_entry" },
	{ 0xedc03953, "iounmap" },
	{ 0x8f9ae7bc, "proc_create" },
	{ 0x4d924f20, "memremap" },
	{ 0x3e321427, "seq_write" },
	{ 0x599fb41c, "kvmalloc_node" },
	{ 0x81888a06, "seq_open" },
	{ 0x9a4114bb, "seq_read" },
	{ 0xc6b24b3e, "seq_lseek" },
	{ 0xe68f4169, "seq_release" },
	{ 0x43b0c9c3, "preempt_schedule" },
	{ 0xa339e6e5, "on_each_cpu_cond_mask" },
	{ 0x5e3240a0, "__cpu_online_mask" },
	{ 0x7a2af7b4, "cpu_number" },
	{ 0x4829a47e, "memcpy" },
	{ 0x7b4627a9, "cpu_hwcap_keys" },
	{ 0x14b89635, "arm64_const_caps_ready" },
	{ 0x92997ed8, "_printk" },
	{ 0x9688de8b, "memstart_addr" },
	{ 0x8da6585d, "__stack_chk_fail" },
	{ 0xb5b54b34, "_raw_spin_unlock" },
	{ 0xba8fbd64, "_raw_spin_lock" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "4156825CCCF40652A11F047");
