#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/thread_info.h>
#include <linux/cred.h>
#include <linux/seccomp.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs_def.h>
#include "selinux/selinux.h"
#endif

#include "policy/allowlist.h"
#include "hook/setuid_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "infra/seccomp_cache.h"
#include "supercall/supercall.h"
#include "hook/tp_marker.h"
#include "feature/kernel_umount.h"

extern void disable_seccomp(void);
extern struct cred *ksu_cred;

#ifdef CONFIG_KSU_SUSFS
extern u32 susfs_zygote_sid;
extern struct work_struct susfs_extra_works;

static inline void ksu_handle_extra_susfs_work(void)
{
    if (work_pending(&susfs_extra_works))
        return;

    schedule_work(&susfs_extra_works);
}

int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    // We only interest in process spwaned by zygote
    if (!susfs_is_sid_equal(current_cred(), susfs_zygote_sid))
        return 0;

    // Check if spawned process is isolated service first, and force to do umount if so
    if (is_isolated_process(ruid))
        goto do_umount;

    // - Since ksu maanger app uid is excluded in allow_list_arr, so ksu_uid_should_umount(manager_uid)
    //   will always return true, that's why we need to explicitly check if new_uid belongs to
    //   ksu manager.
    // - Disable seccomp restriction for KSU manager since running with "su" will disable seccomp anyway
    if (likely(ksu_is_manager_appid_valid()) && unlikely(is_uid_manager(ruid))) {
        disable_seccomp();

        pr_info("install fd for manager: %d\n", ruid);
        ksu_install_fd();
        return 0;
    }

    // we should not umount for webview zygote
    if (unlikely(ruid == WEBVIEW_ZYGOTE_UID))
        return 0;

    // Check if spawned process is normal user app and needs to be umounted
    if (likely(is_appuid(ruid) && ksu_uid_should_umount(ruid)))
        goto do_umount;

    if (ksu_is_allow_uid_for_current(ruid))
        disable_seccomp();

    return 0;

do_umount:
    // Handle kernel umount
    ksu_handle_umount(current_uid().val, ruid);

    // Handle extra susfs work
    ksu_handle_extra_susfs_work();

    // Mark current proc as umounted
    susfs_set_current_proc_umounted();

    return 0;
}
#else
int ksu_handle_setresuid(uid_t old_uid, uid_t new_uid)
{
    // we rely on the fact that zygote always call setresuid(3) with same uids

    pr_info("handle_setresuid from %d to %d\n", old_uid, new_uid);

    if (unlikely(is_uid_manager(new_uid))) {
        disable_seccomp();
        ksu_set_task_tracepoint_flag(current);

        pr_info("install fd for manager: %d\n", new_uid);
        ksu_install_fd();
        return 0;
    }

    if (ksu_is_allow_uid_for_current(new_uid)) {
        disable_seccomp();
        ksu_set_task_tracepoint_flag(current);
    } else {
        ksu_clear_task_tracepoint_flag_if_needed(current);
    }

    // Handle kernel umount
    ksu_handle_umount(old_uid, new_uid);

    return 0;
}
#endif

void __init ksu_setuid_hook_init(void)
{
    ksu_kernel_umount_init();
}

void __exit ksu_setuid_hook_exit(void)
{
    pr_info("ksu_core_exit\n");
    ksu_kernel_umount_exit();
}
