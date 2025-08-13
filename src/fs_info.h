#ifndef FS_INFO_H 
#define FS_INFO_H

#include <linux/dcache.h> 
#include <linux/fs.h>
#include <linux/types.h>
#include "linux/cred.h"
#include "my_idmap.h"

#define DEMO_MAJIC 0x12345678 
#define FS_NAME "demo_fs"

struct __kstatfs_info
{
    u64 total_blocks;
    u64 free_blocks;
    u64 avail_blocks;
    u64 total_inodes;
    u64 free_inodes;
    u32 block_size;
    u32 fragment_size;
    u32 max_name_len;
    u32 fs_flags;
    u32 fs_magic;
}; 

static int demofs_create(struct user_namespace *mnt_userns,
                         struct inode *dir,
                         struct dentry *dentry,
                         umode_t mode,
                         bool excl);

static int demofs_mkdir(struct user_namespace *mnt_userns,
                        struct inode *dir,
                        struct dentry *dentry,
                        umode_t mode);

static int demofs_mknod(struct user_namespace *mnt_userns,
                        struct inode *dir,
                        struct dentry *dentry,
                        umode_t mode,
                        dev_t dev);

static int demofs_symlink(struct user_namespace *mnt_userns,
                          struct inode *dir,
                          struct dentry *dentry,
                          const char *symname);

 
static int demofs_setattr(struct user_namespace *mnt_userns, 
                          struct dentry *dentry,
                          struct iattr *iattr); 
#endif // !FS_INFO_H 
