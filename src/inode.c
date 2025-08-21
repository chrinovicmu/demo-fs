#include <linux/types.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/export.h>
#include <linux/fs_types.h>
#include <linux/mm_types.h>
#include <linux/stat.h>
#include <linux/pagemap.h>
#include <linux/container_of.h>
#include <linux/fortify-string.h>
#include <linux/gfp_types.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/stddef.h>
#include <linux/string.h>

#include "demofs_info.h"
#include "utils.h"
#include "my_idmap.h"

static int demofs_open(struct inode*, struct file*);
static int demofs_release(struct inode*, struct file*); 
static ssize_t demofs_read(struct file *, char __user *, size_t, loff_t*);
static ssize_t demofs_write(struct file *, const char __user*, size_t, loff_t*); 
int demofs_setattr(struct user_namespace *mnt_userns, struct dentry *dentry, struct iattr *iattr);

int demofs_iterate(struct file *file, struct dir_context *ctx);
static int demofs_subdir_create(struct user_namespace *mnt_userns,
                                struct inode *dir, struct dentry *dentry,
                                umode_t mode, bool excl);
static int demofs_subdir_mkdir(struct user_namespace *mnt_userns,
                               struct inode *dir, struct dentry *dentry,
                               umode_t mode);
static int demofs_unlink(struct inode *dit, struct dentry *dentry); 
static int demofs_rmdir(struct inode *dir, struct dentry *dentry); 

static struct inode *demofs_make_inode(struct user_namespace *mnt_userns,
                                       struct super_block *sb, umode_t mode,
                                       dev_t dev);
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

static ssize_t demofs_read(struct file *filp, char __user *ubuf,
                           size_t len, loff_t *off)
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

static ssize_t demofs_write(struct file *filp, const char __user *ubuf, 
                            size_t len, loff_t *off)
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

int demofs_iterate(struct file *file, struct dir_context *ctx)
{
    struct inode *inode = file_inode(file); 
    struct demofs_inode *di = container_of(inode, struct demofs_inode, vsf_inode);
    struct demofs_dentry *dentry; 
    int i = 0 ; 

    list_for_each_entry(dentry, &di->children,list)
    {
        if(i < ctx->pos)
        {
            i++; 
            continue; 
        }
        if(!dir_emit(ctx, dentry->name, strlen(dentry->name), 
                     dentry->inode->i_ino, 
                     S_ISDIR(dentry->mode) ? DT_DIR : DT_REG))
            return 0;  
        ctx->pos++; 
        i++; 
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
    .unlink     = demofs_unlink, 
    .rmdir      = demofs_rmdir, 
    .rename     = simple_rename, 
    .getattr    = simple_getattr, 
}; 

static int demofs_subdir_create(struct user_namespace *mnt_userns,
                                struct inode *dir, 
                                struct dentry *dentry,
                                umode_t mode,
                                bool excl)
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

    // d_instantiate(dentry, inode);
   //  inc_nlink(dir);
   // mark_inode_dirty(dir); 

    return 0; 
}

static int demofs_subdir_mkdir(struct user_namespace *mnt_userns,
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

    set_nlink(inode, 2); 
    inc_nlink(dir);
    d_instantiate(dentry, inode);
    dget(dentry); 
    mark_inode_dirty(dir); 

    return 0; 
}

static int demofs_unlink(struct inode *dir, struct dentry  *dentry)
{
    struct super_block *sb = dir->i_sb; 
    int ret; 
    
    ret = simple_unlink(dir, dentry); 
    if(ret == 0)
    {
        demofs_inc_free_inodes(sb); 
    }
    return ret; 
}

static int demofs_rmdir(struct inode *dir, struct dentry *dentry)
{
    int ret; 

    ret = simple_rmdir(dir, dentry);
    if(!ret)
    {
        demofs_inc_free_inodes(dir->i_sb); 
    }

    return 0; 
}
const struct inode_operations demofs_special_iops = 
{
    .getattr = simple_getattr, 
}; 

/* 
static const struct address_space_operations demofs_aops =
{
        .readahead = generic_file_read_iter, 
        .write_iter = generic_file_write_iter, 
        .mappings_flag = 0;  
}; 
*/ 

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
    struct demofs_inode *parent_di;
    struct demofs_dentry *new_entry;

    if (d_inode(dentry))
        return -EEXIST;

    inode = new_inode(dir->i_sb);
    if (!inode)
        return -ENOMEM;

    inode->i_ino = get_next_ino(); // assign inode number

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

    inode->i_uid = make_kuid(mnt_userns, from_kuid(&init_user_ns, current_fsuid()));
    inode->i_gid = make_kgid(mnt_userns, from_kgid(&init_user_ns, current_fsgid()));
    inode->i_mode = mode;
    inode->i_op = &demofs_file_iops;
    inode->i_fop = &demofs_file_fops;
    inode->i_mtime = inode->i_ctime = inode->i_atime = current_time(inode);

    d_instantiate(dentry, inode);
    dget(dentry);
    mark_inode_dirty(inode);

    // ensure parent i_private exists
    parent_di = dir->i_private;
    if (!parent_di) {
        parent_di = kzalloc(sizeof(*parent_di), GFP_KERNEL);
        if (!parent_di) {
            iput(inode);
            return -ENOMEM;
        }
        INIT_LIST_HEAD(&parent_di->children);
        dir->i_private = parent_di;
    }

    new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
    if (!new_entry) {
        iput(inode);
        return -ENOMEM;
    }

    strlcpy(new_entry->name, dentry->d_name.name, DEMOFS_NAME_LEN_MAX);
    new_entry->inode = inode;
    new_entry->mode = mode;
    INIT_LIST_HEAD(&new_entry->list);

    list_add_tail(&new_entry->list, &parent_di->children);

    return 0;
}


int demofs_mkdir(struct user_namespace *mnt_userns,
                 struct inode *dir,
                 struct dentry *dentry,
                 umode_t mode)
{
    struct inode *inode;
    struct demofs_inode *parent_di;
    struct demofs_dentry *new_entry;

    inode = new_inode(dir->i_sb);
    if (!inode)
        return -ENOMEM;

    inode->i_ino = get_next_ino(); // assign inode number
    inode_init_owner(mnt_userns, inode, dir, S_IFDIR | mode);
    inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
    inode->i_op = &demofs_dir_iops;
    inode->i_fop = &demofs_dir_fops;

    set_nlink(inode, 2);
    inc_nlink(dir);

    d_instantiate(dentry, inode);
    dget(dentry);

    // ensure parent i_private exists
    parent_di = dir->i_private;
    if (!parent_di) {
        parent_di = kzalloc(sizeof(*parent_di), GFP_KERNEL);
        if (!parent_di) {
            iput(inode);
            return -ENOMEM;
        }
        INIT_LIST_HEAD(&parent_di->children);
        dir->i_private = parent_di;
    }

    new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
    if (!new_entry) {
        iput(inode);
        return -ENOMEM;
    }

    strlcpy(new_entry->name, dentry->d_name.name, DEMOFS_NAME_LEN_MAX);
    new_entry->inode = inode;
    new_entry->mode = S_IFDIR | mode;
    INIT_LIST_HEAD(&new_entry->list);

    list_add_tail(&new_entry->list, &parent_di->children);

    return 0;
}

int demofs_mknod(struct user_namespace *mnt_userns,
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

int demofs_symlink(struct user_namespace *mnt_userns,
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

/*called when changing file attributes such as permissons and timestamps &*/ 

int demofs_setattr(struct user_namespace *mnt_userns, 
                          struct dentry *dentry,
                          struct iattr *iattr)
{
    struct inode *inode = d_inode(dentry); 
    struct demofs_file_info *file_info = inode->i_private; 
    struct demofs_fs_info *fs_info = inode->i_sb->s_fs_info; 

    int error;

    error = setattr_prepare(mnt_userns, dentry, iattr);
    if (error)
        return error;

    if ((iattr->ia_valid & ATTR_SIZE) && iattr->ia_size != inode->i_size) 
    {
        u64 old_bytes = file_info ? file_info->data_size : 0; 
        u64 new_bytes = iattr->ia_size; 
        u64 old_blocks = demofs_bytes_to_blocks(old_bytes, fs_info->block_size); 
        u64 new_blocks = demofs_bytes_to_blocks(new_bytes, fs_info->block_size); 

        /*case 1: file is growing */ 
        if(new_blocks > old_blocks)
        {
            u64 need = new_blocks - old_blocks; 
            spin_lock(&fs_info->lock); 

            if(fs_info->free_blocks < need)
            {
                spin_unlock(&fs_info->lock); 
                return -ENOSPC; 
            }
            
            fs_info->free_blocks -= need; 
            fs_info->avail_blocks = fs_info->free_blocks; 

        }

        /*case 2: file is being reduced in sized */ 
        else if (old_blocks > new_blocks)
        {
            u64 give = old_blocks - new_blocks; 
            spin_lock(&fs_info->lock);

            fs_info->free_blocks += give; 
            fs_info->avail_blocks = fs_info->free_blocks; 
            spin_unlock(&fs_info->lock); 
        }

        if(file_info)
        {
            char *new_buf = krealloc(file_info->kbuf, new_bytes, GFP_KERNEL); 
            if(!new_buf && new_bytes > 0)
            {
                spin_lock(&fs_info->lock); 

                if(new_blocks > old_blocks)
                    fs_info->free_blocks += (new_blocks - old_blocks); 

                fs_info->avail_blocks = fs_info->free_blocks; 
                spin_unlock(&fs_info->lock); 

                return -ENOMEM; 
            }

            if(new_bytes > old_bytes)
                memset(new_buf + old_bytes, 0, new_bytes - old_bytes); 

            file_info->kbuf = new_buf; 
            file_info->data_size = new_bytes; 
        }

        truncate_setsize(inode, iattr->ia_size);
    }

    setattr_copy(mnt_userns, inode, iattr);
    mark_inode_dirty(inode);
    return 0;
} 
