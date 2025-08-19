
#ifndef UTILS_H
#define UTILS_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include "demofs_info.h"
/* Convert bytes to number of blocks needed */
static inline u64 demofs_bytes_to_blocks(u64 bytes, u32 block_size)
{
    return (bytes + block_size - 1) / block_size;
}

static void demofs_put_super(struct super_block *sb)
{
    kfree(sb->s_fs_info); 
}

static void demofs_dec_free_nodes(struct super_block *sb)
{
    struct demofs_fs_info *fs_info = sb->s_fs_info; 
    spin_lock(&fs_info->lock);

    if(fs_info->free_inodes)
        fs_info->free_inodes--;

    spin_unlock(&fs_info->lock); 
}

static void demofs_inc_free_inodes(struct super_block *sb)
{
    struct demofs_fs_info *fs_info = sb->s_fs_info; 
    spin_lock(&fs_info->lock); 
    fs_info->free_inodes++; 
    
    spin_unlock(&fs_info->lock); 
}
#endif /* DEMOFS_UTILS_H */
