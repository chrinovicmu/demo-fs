#include <linux/fs.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/types.h> 
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include "fs_info.h"

static int demo_open(struct inode*, struct file*);
static int demo_release(struct inode*, struct file*); 
static ssize_t demo_read(struct file *, char __user *, size_t, loff_t*);
static ssize_t demo_write(struct file *, const char __user*, size_t, loff_t*); 

enum demo_file_state
{
    FILE_NOT_USED, 
    FILE_EXCULSIVE_OPEN, 
}; 

struct demo_file_info  
{
    atomic_t already_open; 
    char *inode_kbuf;
    size_t inode_data_size; 
    int error_pending; 
}; 

static int demo_open(struct inode *inode, struct file *file)
{
    struct demo_file_info *inode_info; 

    inode_info = kmalloc(sizeof(*inode_info), GFP_KERNEL); 
    if(NULL == inode_info)
        return -ENOMEM; 

    atomic_set(&inode_info->already_open, FILE_NOT_USED); 
    inode_info->inode_kbuf = NULL; 
    inode_info->inode_data_size = 0; 
    inode_info->error_pending = 0; 

   if(atomic_cmpxchg(&inode_info->already_open, FILE_NOT_USED, FILE_EXCULSIVE_OPEN) != FILE_NOT_USED)
    {
        kfree(inode_info); 
        inode_info = NULL; 
        return -EBUSY; 
    }
    file->private_data = inode_info; 

    pr_info("%s: File opened: %s\n", FS_NAME, file->f_path.dentry->d_name);

    if(!try_module_get(THIS_MODULE))
    {
        pr_err("Failed to get module reference\n");
        kfree(inode_info);
        inode_info = NULL; 
        return -ENODEV; 
    }

    pr_info("%s: File opened: %s\n", FS_NAME, file->f_path.dentry->d_name);
    return 0; 
}
static int demo_release(struct inode *inode, struct file *file)
{
    struct demo_file_info *inode_info = file->private_data; 
    if(!inode_info)
        return 0; 

    atomic_set(&inode_info->already_open, FILE_NOT_USED); 
    kfree(inode_info->inode_kbuf);
    kfree(inode_info); 
    
    file->private_data = NULL; 
    module_put(THIS_MODULE); 

    pr_info("%s: File closed: %s", FS_NAME, file->f_path.dentry->d_name); 
    return 0; 
}

static ssize_t demo_read(struct file * filp, char __user * ubuf, size_t len, loff_t *off)
{
    struct demo_file_info *inode_info = filp->private_data; 
    size_t bytes_to_read; 

    if(!inode_info || !inode_info->inode_kbuf)
        return 0; 

    if(inode_info->error_pending)
    {
        int err = inode_info->error_pending; 
        inode_info->error_pending = 0; 
        return err; 
    }

    if(*off > inode_info->inode_data_size)
    {
        pr_info("%s: Read at EOF, offset %lld, size %zu\n", FS_NAME, *off, inode_info->inode_data_size); 
        return 0; 
    }

    bytes_to_read = min(len, inode_info->inode_data_size - *off); 
    
    if(copy_to_user(ubuf, inode_info->inode_kbuf + *off, bytes_to_read))
        return -EFAULT; 

    *off += bytes_to_read; 

    pr_info("%s: Read %zu bytes, new offset %lld\n", FS_NAME, bytes_to_read, *off);

    return bytes_to_read; 
}

static ssize_t demo_write(struct file * filp, const char __user * ubuf, size_t len, loff_t *off)
{
    struct demo_file_info *inode_info = filp->private_data;
    size_t bytes_to_write;
    
    if(!inode_info || !inode_info->inode_kbuf)
        return -EINVAL;
    
    if(inode_info->error_pending)
    {
        int err = inode_info->error_pending;
        inode_info->error_pending = 0;
        return err;
    }
    
    if(*off > inode_info->inode_data_size)
    {
        pr_info("%s: Write beyond EOF, offset %lld, size %zu\n", FS_NAME, *off, inode_info->inode_data_size);
        return -EINVAL;
    }
    
    bytes_to_write = min(len, inode_info->inode_data_size - *off);
    
    if(copy_from_user(inode_info->inode_kbuf + *off, ubuf, bytes_to_write))
        return -EFAULT;
    
    *off += bytes_to_write;

    pr_info("%s: Written %zu bytes, new offset %lld\n", FS_NAME, bytes_to_write, *off);
    return bytes_to_write;
}

static const struct file_operations demo_file_ops = 
{
        .owner = THIS_MODULE, 
        .open = demo_open, 
        .release = demo_release, 
        .read = demo_read, 
        .write = demo_write, 
}; 

static const struct inode_operations demo_inode_file_ops = 
{
        .setattr = simple_setattr, 
        .getattr = simple_getattr, 
}; 

int demo_create(struct mnt_idmap *idmap, struct inode *dir,
                struct dentry *dentry, umode_t mode, bool excl)
{
    struct inode *inode;

    if (d_inode(dentry))
        return -EEXIST;

    inode = new_inode(dir->i_sb);
    if (!inode)
        return -ENOMEM;

    /* Map the current process's uid/guid to mnt_idmap */
    inode->i_uid = mnt_idmap_map_user(idmap, current_fsuid());
    inode->i_gid = mnt_idmap_map_group(idmap, current_fsgid());

    inode->i_mode = mode;

    inode->i_op = &demo_inode_file_ops; 
    inode->i_fop = &demo_file_ops;

    inode->i_mtime = inode->i_ctime = inode->i_atime = current_time(inode);

    d_instantiate(dentry, inode);

    dget(dentry);
    mark_inode_dirty(inode);

    return 0;
}
