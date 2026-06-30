#ifndef __KSU_H_SELINUX_HIDE
#define __KSU_H_SELINUX_HIDE

#include <linux/types.h>

void ksu_selinux_hide_init();
void ksu_selinux_hide_exit();
void ksu_selinux_hide_drop_backup_if_unused();
void ksu_selinux_hide_handle_second_stage();
void ksu_selinux_hide_handle_post_fs_data();

extern bool ksu_selinux_hide_running;
extern bool ksu_selinux_hide_enabled;
extern void initialize_fake_status(void);

struct page;
extern struct page *fake_status;

struct static_key_false;
extern struct static_key_false fake_status_initialize_key;

struct selinux_state;
extern struct selinux_state fake_state;

#endif
