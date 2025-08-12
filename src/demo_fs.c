#include <cstddef>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/dcache.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/statfs.h>
#include "asm/page_types.h"
#include "fs_info.h"
#include "linux/gfp_types.h"
#include "linux/slab.h"
#include "linux/stat.h"
#include "fs_info.h"

#define DEMOFS_MAGIC 0x12345678 

static struct dentry *demofs_mount(struct file_system_type *, int, const char*, void *);
static void demofs_kill_sb(struct super_block*sb); 
static int demofs_fill_super(struct super_block *, void*, int); 


static int demofs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    struct super_block *sb = dentry->d_sb; 
    struct __kstatfs_info *stats = sb->s_fs_info; 

    buf->f_type    = stats->fs_magic;
    buf->f_bsize   = stats->block_size;
    buf->f_blocks  = stats->total_blocks;
    buf->f_bfree   = stats->free_blocks;
    buf->f_bavail  = stats->avail_blocks;
    buf->f_files   = stats->total_inodes;
    buf->f_ffree   = stats->free_inodes;
    buf->f_namelen = stats->max_name_len;
    buf->f_frsize  = stats->fragment_size;
    buf->f_flags   = stats->fs_flags;

    return 0; 
}

static struct super_operations demofs_super_ops =
{
        .statfs = demofs_statfs,  
}; 

static struct inode_operations demofs_root_dir_iops = 
{

}; 
static struct file_operations demofs_root_dir_fops =   
{

}; 

static int demofs_fill_super(struct super_block *sb, void * data, int silent)
{
    struct inode *root_inode; 
    struct __kstatfs_info *stats; 

    stats = kzalloc(sizeof(struct __kstatfs_info), GFP_KERNEL); 
    if(NULL == stats)
        return -ENOMEM; 

    stats->total_blocks = 1024;
    stats->free_blocks = 512;
    stats->avail_blocks = 500;
    stats->total_inodes = 100;
    stats->free_inodes = 80;
    stats->block_size = 4096;
    stats->fragment_size = 4096;
    stats->max_name_len = 255;
    stats->fs_flags = 0;
    stats->fs_magic = DEMOFS_MAGIC; 

    sb->s_fs_info = stats; 
    sb->s_magic = stats->fs_magic; 
    sb->s_op = demofs_super_ops;
    sb->s_blocksize = stats->block_size; 
    sb->s_blocksize_bits = PAGE_SHIFT; 

    root_inode = new_inode(sb);
    inode_init_owner(root_inode, NULL, S_IFREG | 0644); 
    root_inode->i_sb = sb; 
    root_inode->i_atime = root_inode->i_ctime = current_time(root_inode); 
    root_inode->i_fop = &demofs_root_dir_fops; 
    root_inode->i_op = &demofs_root_dir_iops;  

    sb->s_root = d_make_root(root_inode); 
}
static struct dentry *demofs_mount(struct file_system_type *fs_type, int flags,
                                  const char *dev_name, void *data) 
{
    pr_info("%s: mounted\n", FS_NAME); 
    return NULL; 
}

static void demofs_kill_sb(struct super_block *sb)
{
    pr_info("%s: unmounted\n", FS_NAME); 
}

static struct file_system_type demofs_type = 
{
        .owner = THIS_MODULE, 
        .name = (const char)FS_MAME, 
        .mount = demofs_mount, 
        .kill_sb = demofs_kill_sb, 
        .fs_flags = 0, 
}; 

static int __init demofs_init(void)
{
    int ret = register_filesystem(&demofs_type); 
    pr_info("%s: registered\n", FS_NAME); 
    
    return ret;
}

static void __exit demofs_exit(void)
{
    unregister_filesystem(&demofs_type); 
    pr_info("%s: unregistered\n", FS_NAME); 
}

module_init(demofs_init); 
module_exit(demofs_exit);

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("Chrinovic M"); 

