
#ifndef MY_IDMAP_H
#define MY_IDMAP_H

#include <linux/uidgid.h>

struct mnt_idmap {
    struct user_namespace *ns;
};

extern kuid_t mnt_idmap_map_user(const struct mnt_idmap *, kuid_t);
extern kgid_t mnt_idmap_map_group(const struct mnt_idmap *, kgid_t);

#endif /* MY_IDMAP_H */
