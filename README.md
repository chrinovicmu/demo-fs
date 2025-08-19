# demofs — A Linux Filesystem

**demofs** is a custom Linux filesystem module written in C. It provides a simple, educational filesystem implementation that integrates with the Linux Virtual Filesystem (VFS) layer.

> ⚠️ **Work in Progress**: Features and interfaces may change until the first stable release.

## Features

- ✅ Functional Linux filesystem with mounting support
- ✅ Basic file operations: create, read, write
- ✅ Directory operations: mkdir, rmdir, ls
- ✅ Thread-safe concurrent access
- ✅ Compatible with Linux VFS layer

## Installation

```bash
# Build the kernel module
make

# Load the module
sudo insmod demofs.ko

# Create mount point and mount
sudo mkdir /mnt/demofs
sudo mount -t demo_fs none /mnt/demofs
```

## Usage

```bash
# Navigate to filesystem
cd /mnt/demofs

# Create files and directories (requires root)
sudo touch file1
sudo mkdir subdir
sudo echo "hello demofs" > file1

# Read files
cat file1
ls -la
```

**Unmount when done:**
```bash
sudo umount /mnt/demofs
sudo rmmod demofs
```

## Current Status

**Working:**
- Module loads successfully
- Mount/unmount operations
- File and directory creation (root only)
- Basic read/write operations

**Known Issues:**
- Non-root users cannot create files/directories
- File metadata shows `?` in `ls -l` output
- Directory isolation needs improvement

## Contributing

Contributions welcome! This is an educational project for learning Linux kernel filesystem development.

**Areas needing work:**
- Fix permission system for non-root users
- Proper inode metadata handling
- Improve directory isolation
- Add comprehensive error handling
