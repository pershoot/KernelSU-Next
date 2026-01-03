#include <linux/security.h>
#include <linux/atomic.h>
#include <linux/version.h>

#include "feature.h"
#include "klog.h"
#include "ksud.h"
#include "seccomp_cache.h"

// sorry for the ifdef hell
// but im too lazy to fragment this out.
// theres only one feature so far anyway
// - xx, 20251019

static u32 su_sid = 0;
static u32 priv_app_sid = 0;

// init as disabled by default
static atomic_t disable_spoof = ATOMIC_INIT(1);

void ksu_avc_spoof_enable();
void ksu_avc_spoof_disable();

#ifndef CONFIG_KSU_SUSFS
static bool ksu_avc_spoof_enabled = true;
#else
static bool ksu_avc_spoof_enabled = false;
extern bool susfs_is_avc_log_spoofing_enabled;
// KP registered (1 (KP active), 0 (not))
static atomic_t ksu_avc_spoof_armed = ATOMIC_INIT(0);
// Defer (can't run within syscall context)
static void ksu_avc_spoof_disable_workfn(struct work_struct *work);
static DECLARE_WORK(ksu_avc_spoof_disable_work, ksu_avc_spoof_disable_workfn);

// Susfs owns; called in to from susfs avc (disabled -> enabled)
void ksu_avc_spoof_susfs_on(void)
{
	if (ksu_avc_spoof_enabled || atomic_read(&ksu_avc_spoof_armed)) {
		pr_info("avc_spoof: SuSFS's AVC spoof enabled; scheduling KSU's feature shutdown\n");
		ksu_avc_spoof_enabled = false;
		atomic_set(&disable_spoof, 1);
		schedule_work(&ksu_avc_spoof_disable_work);
	}
}
#endif
static bool boot_completed = false;

static int avc_spoof_feature_get(u64 *value)
{
#ifdef CONFIG_KSU_SUSFS
	if (susfs_is_avc_log_spoofing_enabled) {
		*value = 0;
		return 0;
	}
#endif

	*value = ksu_avc_spoof_enabled ? 1 : 0;
	return 0;
}

static int avc_spoof_feature_set(u64 value)
{
	bool enable = value != 0;

#ifdef CONFIG_KSU_SUSFS
	// Prevent ksu avc enablement (during susfs avc)
	if (enable && susfs_is_avc_log_spoofing_enabled) {
		pr_info("avc_spoof: KSU's AVC spoof request ignored; SuSFS's feature active\n");
		return -EBUSY;
	}
#endif

	if (enable == ksu_avc_spoof_enabled) {
		pr_info("avc_spoof: no need to change\n");
		return 0;
	}

	ksu_avc_spoof_enabled = enable;

	if (boot_completed) {
		if (enable) {
			ksu_avc_spoof_enable();
		} else {
			ksu_avc_spoof_disable();
		}
	}

	pr_info("avc_spoof: set to %d\n", enable);

	return 0;
}

static const struct ksu_feature_handler avc_spoof_handler = {
	.feature_id = KSU_FEATURE_AVC_SPOOF,
	.name = "avc_spoof",
	.get_handler = avc_spoof_feature_get,
	.set_handler = avc_spoof_feature_set,
};

static int get_sid()
{
	// dont load at all if we cant get sids
	int err = security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &su_sid);
	if (err) {
		pr_info("avc_spoof/get_sid: su_sid not found!\n");
		return -1;
	}
	pr_info("avc_spoof/get_sid: su_sid: %u\n", su_sid);

	err = security_secctx_to_secid("u:r:priv_app:s0:c512,c768", strlen("u:r:priv_app:s0:c512,c768"), &priv_app_sid);
	if (err) {
		pr_info("avc_spoof/get_sid: priv_app_sid not found!\n");
		return -1;
	}
	pr_info("avc_spoof/get_sid: priv_app_sid: %u\n", priv_app_sid);
	return 0;
}

int ksu_handle_slow_avc_audit(u32 *tsid)
{
	if (atomic_read(&disable_spoof))
		return 0;

	// if tsid is su, we just replace it
	// unsure if its enough, but this is how it is aye?
	if (*tsid == su_sid) {
		pr_info("avc_spoof/slow_avc_audit: replacing su_sid: %u with priv_app_sid: %u\n", su_sid, priv_app_sid);
		*tsid = priv_app_sid;
	}

	return 0;
}

#ifdef CONFIG_KPROBES
#include <linux/kprobes.h>
#include <linux/slab.h>
#include "arch.h"
static struct kprobe *slow_avc_audit_kp;
//	.symbol_name = "slow_avc_audit",
//	.pre_handler = slow_avc_audit_pre_handler,
static int slow_avc_audit_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
#ifdef CONFIG_KSU_SUSFS
	// Check (prevents dual spoofing)
	if (susfs_is_avc_log_spoofing_enabled) {
		pr_info("avc_spoof: SuSFS's AVC spoof active; skipping KSU's feature\n");
		return 0;
	}
#endif

	if (atomic_read(&disable_spoof))
		return 0;

	/* 
	 * for < 4.17 int slow_avc_audit(u32 ssid, u32 tsid
	 * for >= 4.17 int slow_avc_audit(struct selinux_state *state, u32 ssid, u32 tsid
	 * for >= 6.4 int slow_avc_audit(u32 ssid, u32 tsid
	 * not to mention theres also DKSU_HAS_SELINUX_STATE
	 * since its hard to make sure this selinux state thing 
	 * cross crossing with 4.17 ~ 6.4's where slow_avc_audit
	 * changes abi (tsid in arg2 vs arg3)
	 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	u32 *tsid = (u32 *)&PT_REGS_PARM2(regs);
	ksu_handle_slow_avc_audit(tsid);
#else
	u32 *tsid = (u32 *)&PT_REGS_PARM3(regs);
	ksu_handle_slow_avc_audit(tsid);
#endif

	return 0;
}

// copied from upstream
static struct kprobe *init_kprobe(const char *name,
				  kprobe_pre_handler_t handler)
{
	struct kprobe *kp = kzalloc(sizeof(struct kprobe), GFP_KERNEL);
	if (!kp)
		return NULL;
	kp->symbol_name = name;
	kp->pre_handler = handler;

	int ret = register_kprobe(kp);
	pr_info("sucompat: register_%s kprobe: %d\n", name, ret);
	if (ret) {
		kfree(kp);
		return NULL;
	}

	return kp;
}
static void destroy_kprobe(struct kprobe **kp_ptr)
{
	struct kprobe *kp = *kp_ptr;
	if (!kp)
		return;
	unregister_kprobe(kp);
	synchronize_rcu();
	kfree(kp);
	*kp_ptr = NULL;
}
#endif // CONFIG_KPROBES

void ksu_avc_spoof_disable(void)
{
#if defined(CONFIG_KPROBES) && defined(CONFIG_KSU_SUSFS)
	// Only one caller (worker / direct; KP tear down)
	if (atomic_cmpxchg(&ksu_avc_spoof_armed, 1, 0)) {
		pr_info("avc_spoof/exit: unregister slow_avc_audit kprobe!\n");
		destroy_kprobe(&slow_avc_audit_kp);
	}
#elif defined(CONFIG_KPROBES)
	pr_info("avc_spoof/exit: unregister slow_avc_audit kprobe!\n");
	destroy_kprobe(&slow_avc_audit_kp);
#endif
	atomic_set(&disable_spoof, 1);
	pr_info("avc_spoof/exit: slow_avc_audit spoofing disabled!\n");
}

#ifdef CONFIG_KSU_SUSFS
static void ksu_avc_spoof_disable_workfn(struct work_struct *work)
{
	// Deferred (teardown with flag (armed) via cmpxchg)
	pr_info("avc_spoof: deferred; disable / unregister (slow_avc_audit kprobe)\n");
	ksu_avc_spoof_disable();
}
#endif

void ksu_avc_spoof_enable(void) 
{
	int ret = get_sid();
	if (ret) {
		pr_info("avc_spoof/init: sid grab fail!\n");
		return;
	}

#ifdef CONFIG_KPROBES
	pr_info("avc_spoof/init: register slow_avc_audit kprobe!\n");
	slow_avc_audit_kp = init_kprobe("slow_avc_audit", slow_avc_audit_pre_handler);
#endif	
	// once we get the sids, we can now enable the hook handler
#ifdef CONFIG_KSU_SUSFS
	// KP active marker (used by susfs for shutdown)
	atomic_set(&ksu_avc_spoof_armed, 1);
#endif
	atomic_set(&disable_spoof, 0);
	
	pr_info("avc_spoof/init: slow_avc_audit spoofing enabled!\n");
}

void ksu_avc_spoof_late_init()
{
	boot_completed = true;
	
    if (ksu_avc_spoof_enabled) {
		ksu_avc_spoof_enable();
	}
}

void ksu_avc_spoof_init()
{
	if (ksu_register_feature_handler(&avc_spoof_handler)) {
		pr_err("Failed to register avc spoof feature handler\n");
	}
}

void ksu_avc_spoof_exit()
{
	if (ksu_avc_spoof_enabled) {
		ksu_avc_spoof_disable();
	}
	ksu_unregister_feature_handler(KSU_FEATURE_AVC_SPOOF);
}
