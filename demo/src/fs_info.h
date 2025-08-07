#ifndef FS_INFO_H 
#define FS_INFO_H

#include "linux/dcache.h"
#include "linux/fs.h"
#include <linux/types.h>

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

extern const struct inode_operations demo_inode_ops;
extern const struct file_operations demo_file_ops;

int demo_create(struct mnt_idmap *idmap, ,struct inode *dir,
                struct dentry *dentry, umode_t mode, bool excl); 


#endif // !FS_INFO_H 
