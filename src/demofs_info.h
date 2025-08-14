#ifndef FS_INFO_H 
#define FS_INFO_H

#include <linux/dcache.h> 
#include <linux/fs.h>
#include <linux/types.h>
#include "linux/cred.h"
#include "linux/spinlock_types.h"
#include "my_idmap.h"

#define DEMO_MAJIC 0x12345678 
#define FS_NAME "demo_fs"

#define DEMOFS_TOTAL_SIZE (4 * 1024 * 1024)
#define DEMOFS_INODES_TOTAL 100
#define DEMOFS_BLOCK_SIZE   4096
#define DEMOFS_NAME_LEN_MAX 255

#define DEMOFS_DEFAULT_SIZE_MB 16 

struct demofs_fs_info 
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

    spinlock_t lock;  
}; 

enum demofs_file_state
{
    FILE_NOT_USED, 
    FILE_EXCLUSIVE_OPEN, 
}; 

struct demofs_file_info  
{
    atomic_t already_open; 
    char *kbuf;
    size_t data_size; 
    int error_pending; 
}; 

static int demofs_iterate(struct file *file, struct dir_context *ctx); 

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
