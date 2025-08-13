#include <linux/fs.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/export.h>
#include <linux/fs_types.h>
#include <linux/mm_types.h>
#include <linux/stat.h>

#include "fs_info.h"
#include "my_idmap.h"

static int demofs_open(struct inode*, struct file*);
static int demofs_release(struct inode*, struct file*); 
static ssize_t demofs_read(struct file *, char __user *, size_t, loff_t*);
static ssize_t demofs_write(struct file *, const char __user*, size_t, loff_t*); 
static int demofs_setattr(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *iattr);

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

static int demofs_open(struct inode *inode, struct file *file)
{
    struct demofs_file_info *info = inode->i_private; 

    if (!info)
        return -EINVAL;

    if (atomic_cmpxchg(&info->already_open, FILE_NOT_USED, FILE_EXCLUSIVE_OPEN) != FILE_NOT_USED)
        return -EBUSY;

    file->private_data = info; 

    if (!try_module_get(THIS_MODULE)) {
        atomic_set(&info->already_open, FILE_NOT_USED);
        return -ENODEV; 
    }

    pr_info("%s: File opened: %s\n", FS_NAME, file->f_path.dentry->d_name.name);
    return 0; 
}

static int demofs_release(struct inode *inode, struct file *file)
{
    struct demofs_file_info *info = file->private_data; 
    if (!info)
        return 0; 

    atomic_set(&info->already_open, FILE_NOT_USED); 
    file->private_data = NULL; 
    module_put(THIS_MODULE); 

    pr_info("%s: File closed: %s\n", FS_NAME, file->f_path.dentry->d_name.name); 
    return 0; 
}

static ssize_t demofs_read(struct file *filp, char __user *ubuf, size_t len, loff_t *off)
{
    struct demofs_file_info *info = filp->private_data; 
    size_t bytes_to_read; 

    if (!info || !info->kbuf)
        return 0; 

    if (info->error_pending)
    {
        int err = info->error_pending; 
        info->error_pending = 0; 
        return err; 
    }

    if (*off >= info->data_size) 
    {
        pr_info("%s: Read at EOF, offset %lld, size %zu\n", FS_NAME, *off, info->data_size); 
        return 0; 
    }

    bytes_to_read = min(len, info->data_size - *off); 
    
    if (copy_to_user(ubuf, info->kbuf + *off, bytes_to_read))
        return -EFAULT; 

    *off += bytes_to_read; 

    pr_info("%s: Read %zu bytes, new offset %lld\n", FS_NAME, bytes_to_read, *off);

    return bytes_to_read; 
}

static ssize_t demofs_write(struct file *filp, const char __user *ubuf, size_t len, loff_t *off)
{
    struct demofs_file_info *info = filp->private_data;
    size_t bytes_to_write;
    
    if (!info || !info->kbuf)
        return -EINVAL;
    
    if (info->error_pending) 
    {
        int err = info->error_pending;
        info->error_pending = 0;
        return err;
    }
    
    if (*off > info->data_size) 
    {
        pr_info("%s: Write beyond EOF, offset %lld, size %zu\n", FS_NAME, *off, info->data_size);
        return -EINVAL;
    }
    
    bytes_to_write = min(len, info->data_size - *off);
    
    if (copy_from_user(info->kbuf + *off, ubuf, bytes_to_write))
        return -EFAULT;
    
    *off += bytes_to_write;

    pr_info("%s: Written %zu bytes, new offset %lld\n", FS_NAME, bytes_to_write, *off);
    return bytes_to_write;
}

static struct file_operations demofs_file_fops = 
{
    .owner      = THIS_MODULE, 
    .open       = demofs_open, 
    .release    = demofs_release, 
    .read       = demofs_read, 
    .write      = demofs_write, 
}; 

static struct inode_operations demofs_file_iops = 
{
    .setattr = demofs_setattr, 
    .getattr = simple_getattr, 
}; 

static int demofs_iterate(struct file *file, struct dir_context *ctx)
{
    struct inode *inode = file_inode(file); 
    u64 ino = inode->i_ino; 

    pr_info("%s: readdir called\n", FS_NAME); 

    if (ctx->pos == 0) {
        if (!dir_emit(ctx, ".", 1, ino, DT_DIR))
            return 0; 
        ctx->pos++; 
    }

    if (ctx->pos == 1) {
        if (!dir_emit(ctx, "..", 2, 2, DT_DIR))
            return 0; 
        ctx->pos++; 
    }

    if (ctx->pos == 2) {
        if (!dir_emit(ctx, "file1", 5, 12345, DT_REG))
            return 0; 
        ctx->pos++; 
    }

    return 0; 
}

static const struct file_operations demofs_dir_fops = 
{
    .iterate_shared = demofs_iterate,
}; 

static const struct inode_operations demofs_dir_iops = 
{
    .lookup     = simple_lookup, 
    .create     = demofs_subdir_create, 
    .mkdir      = demofs_subdir_mkdir, 
    .unlink     = simple_unlink, 
    .rmdir      = simple_rmdir, 
    .rename     = simple_rename, 
    .getattr    = simple_getattr, 
}; 

static int demofs_subdir_create(struct user_namespace *mnt_userns, struct inode *dir, 
                                struct dentry *dentry, umode_t mode, bool excl)
{
    struct inode *inode; 
    struct demofs_file_info *info;

    inode = new_inode(dir->i_sb); 
    if (!inode)
        return -ENOMEM; 

    info = kzalloc(sizeof(*info), GFP_KERNEL);
    if (!info) {
        iput(inode);
        return -ENOMEM;
    }

    atomic_set(&info->already_open, FILE_NOT_USED); 
    info->kbuf = NULL; 
    info->data_size = 0; 
    info->error_pending = 0; 

    inode->i_private = info;
    inode->i_ino = get_next_ino(); 
    inode_init_owner(mnt_userns, inode, dir, mode); 
    inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode); 
    
    inode->i_op = &demofs_file_iops; 
    inode->i_fop = &demofs_file_fops; 

    d_instantiate(dentry, inode);
    inc_nlink(dir);
    mark_inode_dirty(dir); 

    return 0; 
}

static int demofs_subdir_mkdir(struct user_namespace *mnt_userns, struct inode *dir,
                               struct dentry *dentry, umode_t mode)
{
    struct inode *inode; 

    inode = new_inode(dir->i_sb); 
    if (!inode)
        return -ENOMEM; 

    inode->i_ino = get_next_ino(); 
    inode_init_owner(mnt_userns, inode, dir, S_IFDIR | mode); 
    inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode); 

    inode->i_op = &demofs_dir_iops; 
    inode->i_fop = &demofs_dir_fops; 

    inode->i_nlink = 2; 
    inc_nlink(dir);
    d_instantiate(dentry, inode);
    dget(dentry); 
    mark_inode_dirty(dir); 

    return 0; 
}

const struct inode_operations demofs_special_iops = 
{
    .getattr = simple_getattr, 
}; 

static struct inode *demofs_make_inode(struct user_namespace *mnt_userns,
                                       struct super_block *sb,
                                       umode_t mode,
                                       dev_t dev)
{
    struct inode *inode;
    struct demofs_file_info *info = NULL;

    inode = new_inode(sb);
    if (!inode)
        return NULL;

    if (S_ISREG(mode)) 
    {
        info = kzalloc(sizeof(*info), GFP_KERNEL);
        if (!info) 
        {
            iput(inode);
            return NULL;
        }
        atomic_set(&info->already_open, FILE_NOT_USED); 
        info->kbuf = NULL; 
        info->data_size = 0; 
        info->error_pending = 0; 
        inode->i_private = info;
    }

    inode_init_owner(mnt_userns, inode, NULL, mode);
    inode->i_ino = get_next_ino();
    inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);

    if (S_ISREG(mode)) 
    {
        inode->i_op = &demofs_file_iops;
        inode->i_fop = &demofs_file_fops;

    } else if (S_ISDIR(mode)) 
    {
        inode->i_op = &demofs_dir_iops;
        inode->i_fop = &demofs_dir_fops;
        inc_nlink(inode);

    } else if (S_ISCHR(mode) || S_ISBLK(mode) || S_ISFIFO(mode) || S_ISSOCK(mode)) 
    {
        init_special_inode(inode, mode, dev);
        inode->i_op = &demofs_special_iops;
    }

    return inode;
}

int demofs_create(struct user_namespace *mnt_userns,
                  struct inode *dir,
                  struct dentry *dentry,
                  umode_t mode,
                  bool excl)
{
    struct inode *inode;
    struct demofs_file_info *info;

    if (d_inode(dentry))
        return -EEXIST;

    inode = new_inode(dir->i_sb);
    if (!inode)
        return -ENOMEM;

    info = kzalloc(sizeof(*info), GFP_KERNEL);
    if (!info) 
    {
        iput(inode);
        return -ENOMEM;
    }

    atomic_set(&info->already_open, FILE_NOT_USED); 
    info->kbuf = NULL; 
    info->data_size = 0; 
    info->error_pending = 0; 
    inode->i_private = info;

    inode->i_uid = make_kuid(mnt_userns, from_kuid(&init_user_ns, current_fsuid()));
    inode->i_gid = make_kgid(mnt_userns, from_kgid(&init_user_ns, current_fsgid()));
    inode->i_mode = mode;

    inode->i_op = &demofs_file_iops; 
    inode->i_fop = &demofs_file_fops;

    inode->i_mtime = inode->i_ctime = inode->i_atime = current_time(inode);

    d_instantiate(dentry, inode);
    dget(dentry);

    mark_inode_dirty(inode);

    return 0;
}

static int demofs_mkdir(struct user_namespace *mnt_userns,
                        struct inode *dir,
                        struct dentry *dentry,
                        umode_t mode)
{
    struct inode *inode;

    inode = new_inode(dir->i_sb);
    if (!inode)
        return -ENOMEM;

    inode->i_ino = get_next_ino();

    inode_init_owner(mnt_userns, inode, dir, S_IFDIR | mode);
    inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);

    inode->i_op = &demofs_dir_iops;
    inode->i_fop = &demofs_dir_fops;

    inc_nlink(dir);
    d_instantiate(dentry, inode);
    dget(dentry);

    return 0;
}

static int demofs_mknod(struct user_namespace *mnt_userns,
                        struct inode *dir,
                        struct dentry *dentry,
                        umode_t mode,
                        dev_t dev)
{
    struct inode *inode;

    inode = demofs_make_inode(mnt_userns, dir->i_sb, mode, dev);
    if (!inode)
        return -ENOMEM;

    d_instantiate(dentry, inode);
    dir->i_mtime = dir->i_ctime = current_time(dir);

    return 0;
}

static int demofs_symlink(struct user_namespace *mnt_userns,
                          struct inode *dir,
                          struct dentry *dentry, 
                          const char *symname)
{
    struct inode *inode; 

    if (d_inode(dentry))
        return -EEXIST; 

    inode = new_inode(dir->i_sb); 
    if (!inode)
        return -ENOMEM; 

    inode_init_owner(mnt_userns, inode, dir, S_IFLNK | 0777); 
    inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode); 

    inode->i_op = &simple_symlink_inode_operations; 
    inode->i_size = strlen(symname); 

    d_instantiate(dentry, inode); 
    dget(dentry); 

    return page_symlink(inode, symname, strlen(symname)); 
}


static int demofs_setattr(struct user_namespace *mnt_userns,
                          struct dentry *dentry,
                          struct iattr *iattr)
{
    struct inode *inode = d_inode(dentry);
    struct demofs_file_info *info = inode->i_private;
    int error;

    error = setattr_prepare(mnt_userns, dentry, iattr);
    if (error)
        return error;

    if ((iattr->ia_valid & ATTR_SIZE) && iattr->ia_size != inode->i_size) 
    {
        char *new_buf = krealloc(info->kbuf, iattr->ia_size, GFP_KERNEL);
        if (!new_buf && iattr->ia_size > 0)
            return -ENOMEM;

        if (iattr->ia_size > info->data_size)
            memset(new_buf + info->data_size, 0, iattr->ia_size - info->data_size);

        info->kbuf = new_buf;
        info->data_size = iattr->ia_size;
        truncate_setsize(inode, iattr->ia_size);
    }

    setattr_copy(mnt_userns, inode, iattr);

    mark_inode_dirty(inode);
    return 0;
} 
