#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/dcache.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/statfs.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/log2.h>
#include <linux/minmax.h>
#include <linux/spinlock.h>

#include "demofs_info.h"
#include "utils.h"

#define DEMOFS_MAGIC 0x12345678 

static struct dentry *demofs_mount(struct file_system_type *, int, const char*, void *);
static void demofs_kill_sb(struct super_block*sb); 
static int demofs_fill_super(struct super_block *, void*, int); 


static int demofs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    struct demofs_fs_info *fs_info = dentry->d_sb->s_fs_info;
    unsigned long long id = (unsigned long long)dentry->d_sb->s_dev; 

    buf->f_type    = fs_info->fs_magic;
    buf->f_bsize   = fs_info->block_size;
    buf->f_blocks  = fs_info->total_blocks;
    buf->f_bfree   = fs_info->free_blocks;
    buf->f_bavail  = fs_info->avail_blocks;
    buf->f_files   = fs_info->total_inodes;
    buf->f_ffree   = fs_info->free_inodes;
    buf->f_namelen = fs_info->max_name_len;
    buf->f_frsize  = fs_info->fragment_size;
    buf->f_flags   = fs_info->fs_flags;
    buf->f_fsid.val[0] = (u32)id;
    buf->f_fsid.val[1] = (u32)(id >> 32);

    return 0; 
}

static struct super_operations demofs_super_ops =
{
        .statfs = demofs_statfs,  
        .put_super = demofs_put_super, 
}; 

static struct inode_operations demofs_root_dir_iops = 
{
        .create     = demofs_create, 
        .mkdir      = demofs_mkdir,
        .mknod      = demofs_mknod,
        .setattr    = demofs_setattr, 
        .symlink    = demofs_symlink, 
        .lookup     = simple_lookup, 
        .unlink     = simple_unlink, 
        .rmdir      = simple_rmdir, 
        .rename     = simple_rename, 
        .getattr    = simple_getattr,
        .permission = generic_permission, 
}; 

static struct file_operations demofs_root_dir_fops =   
{
        .owner = THIS_MODULE,
        .open  = dcache_dir_open, 
        .release = dcache_dir_close, 
        .llseek = generic_file_llseek, 
        .iterate_shared = demofs_iterate, 
}; 

static int demofs_fill_super(struct super_block *sb, void * data, int silent)
{
    struct inode *root_inode; 
    struct demofs_fs_info *fs_info;     
    size_t fs_bytes;

    fs_info = kzalloc(sizeof(struct demofs_fs_info *), GFP_KERNEL); 
    if(!fs_info)
        return -ENOMEM; 

    fs_bytes = DEMOFS_DEFAULT_SIZE_MB * 1024ULL *1023ULL; 

    fs_info->block_size = PAGE_SIZE; 
    fs_info->fragment_size = fs_info->block_size;
    fs_info->max_name_len = DEMOFS_NAME_LEN_MAX; 
    fs_info->fs_flags = 0; 
    fs_info->fs_magic = DEMOFS_MAGIC; 

    fs_info->total_blocks = fs_bytes / fs_info->block_size;
    fs_info->free_blocks = fs_info->total_blocks; 
    fs_info->avail_blocks = fs_info->free_blocks; 

    // Policy: 1 node per 16 block

    fs_info->total_inodes = max_t(u64, 16, fs_info->total_blocks / 16);
    fs_info->free_inodes = fs_info->total_inodes; 

    spinlock_init(&fs_info->lock); 

    sb->s_fs_info = fs_info; 
    sb->s_magic = fs_info->fs_magic; 
    sb->s_op = &demofs_super_ops;
    sb->s_blocksize = fs_info->block_size; 
    sb->s_blocksize_bits = ilog2(fs_info->block_size); 

    root_inode = new_inode(sb);
    if(!root_inode)
        return -ENOMEM; 

    inode_init_owner(&init_user_ns, root_inode, NULL, S_IFREG | 0755); 
    root_inode->i_sb = sb; 
    root_inode->i_atime = root_inode->i_ctime = current_time(root_inode); 
    root_inode->i_fop = &demofs_root_dir_fops; 
    root_inode->i_op = &demofs_root_dir_iops;  

    sb->s_root = d_make_root(root_inode); 
    if(!sb->s_root)
        return -ENOMEM; 
    
    return 0; 
}
static struct dentry *demofs_mount(struct file_system_type *fs_type, int flags,
                                  const char *dev_name, void *data) 
{
    struct dentry *dentry; 

    /*file-system is not on a physical device*/ 
    dentry = mount_nodev(fs_type, flags, data, demofs_fill_super); 

    if(IS_ERR(dentry))
        pr_err("%s: mount failed\n", FS_NAME); 
    else 
        pr_info("%s: mounted\n", FS_NAME); 

    return dentry; 
}

static void demofs_kill_sb(struct super_block *sb)
{
    pr_info("%s: unmounted\n", FS_NAME); 
}

static struct file_system_type demofs_type = 
{
        .owner      = THIS_MODULE, 
        .name       = FS_NAME, 
        .mount      = demofs_mount, 
        .kill_sb    = demofs_kill_sb, 
        .fs_flags   = 0, 
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

