#ifndef __KSU_H_UID_OBSERVER
#define __KSU_H_UID_OBSERVER

#include <linux/namei.h>
#include <linux/spinlock.h>

void ksu_throne_tracker_init();

void ksu_throne_tracker_exit();

void track_throne(bool prune_only);

/*
 * small helper to check if lock is held / file stability
 * false - file is stable
 * true  - file is being deleted / renamed | written / replaced
 *
 */
static inline bool is_lock_held(const char *path)
{
	struct path kpath;

	// kern_path returns 0 on success
	if (kern_path(path, 0, &kpath))
		return true;

	// just being defensive
	if (!kpath.dentry) {
		path_put(&kpath);
		return true;
	}

	// Dentry (deleted / renamed)
	if (!spin_trylock(&kpath.dentry->d_lock)) {
		pr_info("%s: lock held, bail out!\n", __func__);
		path_put(&kpath);
		return true;
	}

	// trylock succeeded; no dentry locked

	spin_unlock(&kpath.dentry->d_lock);

	// Inode (written / replaced)
	if (inode_is_locked(kpath.dentry->d_inode)) {
		path_put(&kpath);
		return true;
	}

	path_put(&kpath);
	return false;
}

#endif
