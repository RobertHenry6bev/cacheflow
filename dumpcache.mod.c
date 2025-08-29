#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

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



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xba8fbd64, "_raw_spin_lock" },
	{ 0xb5b54b34, "_raw_spin_unlock" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x9688de8b, "memstart_addr" },
	{ 0x92997ed8, "_printk" },
	{ 0x921b07b1, "__cpu_online_mask" },
	{ 0xa65c6def, "alt_cb_patch_nops" },
	{ 0xf6e4df71, "on_each_cpu_cond_mask" },
	{ 0x43b0c9c3, "preempt_schedule" },
	{ 0xba24ed49, "seq_release" },
	{ 0xa17b3395, "seq_lseek" },
	{ 0x78df8acc, "seq_read" },
	{ 0xff597603, "seq_open" },
	{ 0xfc4245da, "__kvmalloc_node_noprof" },
	{ 0x82ca09ce, "seq_write" },
	{ 0x4d924f20, "memremap" },
	{ 0x0683b261, "proc_create" },
	{ 0xedc03953, "iounmap" },
	{ 0x1f232ba6, "remove_proc_entry" },
	{ 0x32263340, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "4255B329BF022AA63BEF5AD");
