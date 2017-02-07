#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/rwlock.h>
#include <asm/uaccess.h>
#include "procdetails.h"

static char buf[BUF];
static struct _proc_details_ proc_details;
static void* subdir_lock;
static subdir_find_t subdir_find = NULL;
static xlate_t xlate = NULL;
static syms_lookup_t syms_lookup = NULL;
static symbol_name_t symbol_name = NULL;

static void get_details(void);


// ----------------------------------------------------------------------------------------------------------
struct proc_dir_entry {
    unsigned int low_ino;
    umode_t mode;
    nlink_t nlink;
    kuid_t uid;
    kgid_t gid;
    loff_t size;
    const struct inode_operations *proc_iops;
    const struct file_operations *proc_fops;
    struct proc_dir_entry *parent;
    struct rb_root subdir;
    struct rb_node subdir_node;
    void *data;
    atomic_t count;
    atomic_t in_use;
    struct completion *pde_unload_completion;
    struct list_head pde_openers;
    spinlock_t pde_unload_lock;
    u8 namelen;
    char name[];
};

// ----------------------------------------------------------------------------------------------------------
static int proc_procreadwrite_show (struct seq_file *m, void *v) {
    size_t spacing;
    char spacing_left[] = "                                                   ";

    if(!proc_details.filename[0]) {
        return -ENOENT;
    }
    
    spacing = (60 - strlen(proc_details.filename) - 6) / 2;
    if(spacing < 0 || spacing >= 60) {
        spacing = 0;
    }
    spacing_left[spacing] = 0;

    snprintf(buf, BUF, "------------------------------------------------------------\n%s/proc/%s"
        "\n------------------------------------------------------------\n", spacing_left, proc_details.filename);
    
    snprintf(buf, BUF, "%s> %-42s : %s\n", buf, "Module ", proc_details.modname); 
    snprintf(buf, BUF, "%s> %-42s\n", buf, "Mode "); 
    snprintf(buf, BUF, "%s      %-38s : %o\n", buf, "Format ", (proc_details.dir_entry->mode & 0170000) / (8 * 8 * 8));
    snprintf(buf, BUF, "%s      %-38s : %o\n", buf, "Permissions ", proc_details.dir_entry->mode & 0777);
    snprintf(buf, BUF, "%s> %-42s : %zd\n", buf, "Count ", (size_t)(proc_details.dir_entry->count.counter)); 
    snprintf(buf, BUF, "%s> %-42s : %zd\n", buf, "In use ", (size_t)(proc_details.dir_entry->in_use.counter)); 
    
    snprintf(buf, BUF, "%s> %-42s : %s\n", buf, "File Operations ", proc_details.fops[0] ? "Yes" : "No");
    if(proc_details.fops[0]) {
        snprintf(buf, BUF, "%s    %s = {\n", buf, proc_details.fops);
        SHOW_FUNCTION(open)
        SHOW_FUNCTION(read)
        SHOW_FUNCTION(write)
        SHOW_FUNCTION(release)
        SHOW_FUNCTION(llseek)
        snprintf(buf, BUF, "%s    };\n", buf);
    }
    
    seq_puts(m, buf);
    return 0;
}


// ----------------------------------------------------------------------------------------------------------
static int proc_procreadwrite_open (struct inode *inode, struct file *file) {
    return single_open (file, proc_procreadwrite_show, NULL);
}


// ----------------------------------------------------------------------------------------------------------
static ssize_t proc_procreadwrite_write (struct file *file, const char * buf, size_t size, loff_t * ppos) {
    size_t len = 255;
    size_t i;
    
    if (len > size) {
        len = size;
    }

    if (copy_from_user (proc_details.filename, buf, len)) {
        return -EFAULT;
    }

    proc_details.filename[len] = 0;
    for(i = 0; i < len; i++) {
        if(proc_details.filename[i] == '\r' || proc_details.filename[i] == '\n') {
            proc_details.filename[i] = 0;
            break;
        }
    }

    printk(KERN_INFO MOD "checking module: %s\n", proc_details.filename);
    get_details();
    return len;
}



// ----------------------------------------------------------------------------------------------------------
static struct file_operations proc_procreadwrite_operations = {
    .open = proc_procreadwrite_open,
    .read = seq_read,
    .write = proc_procreadwrite_write,
    .llseek = seq_lseek,
    .release = single_release,
};



// ----------------------------------------------------------------------------------------------------------
static void get_details() {
    int rv;
    size_t len;
    size_t symbolsize, offset;
    const char* fn = proc_details.filename;
    char *modname = NULL;
    char namebuf[128];
    
    spin_lock(subdir_lock);
    rv = xlate(proc_details.filename, &(proc_details.dir_entry), &fn);
    printk(KERN_INFO MOD "Ret: %d, Residual: %s\n", rv, fn);
    if(rv != 0) {
        spin_unlock(subdir_lock);
        return;
    }
    len = strlen(fn);
    // find entry in procfs
    proc_details.dir_entry = subdir_find(proc_details.dir_entry, fn, len);
    if(proc_details.dir_entry) {
        printk(KERN_INFO MOD "Name: %s, proc fops: %p\n", proc_details.dir_entry->name, proc_details.dir_entry->proc_fops);
        // get module name
        (void)syms_lookup((size_t)(proc_details.dir_entry->proc_fops), &symbolsize, &offset, &modname, namebuf);
        if(modname) {
            strlcpy(proc_details.modname, modname, 128);
        } else {
            strcpy(proc_details.modname, "Kernel");
        }
        // get file operation struct name
        symbol_name((size_t)(proc_details.dir_entry->proc_fops), proc_details.fops);    
        // check which functions are registered
        GET_FUNCTION(open)
        GET_FUNCTION(read)
        GET_FUNCTION(write)
        GET_FUNCTION(release)
        GET_FUNCTION(llseek)
    }
    spin_unlock(subdir_lock);
}


// ----------------------------------------------------------------------------------------------------------
static int __init procdetails_init(void)
{
    printk(KERN_INFO MOD "module start\n");

    proc_create("procdetails", 0666, NULL, &proc_procreadwrite_operations);
        
    xlate = (xlate_t)kallsyms_lookup_name("__xlate_proc_name");   
    if(!xlate) {
        printk(KERN_INFO MOD "__xlate_proc_name not found!\n");
        goto err;
    }
    subdir_lock = (void*)kallsyms_lookup_name("proc_subdir_lock");
    if(!subdir_lock) {
        printk(KERN_INFO MOD "proc_subdir_lock not found!\n");
        goto err;
    }
    subdir_find = (subdir_find_t)kallsyms_lookup_name("pde_subdir_find");
    if(!subdir_find) {
        printk(KERN_INFO MOD "pde_subdir_find not found!\n");
        goto err;
    }
    syms_lookup = (syms_lookup_t)kallsyms_lookup_name("kallsyms_lookup");
    if(!syms_lookup) {
        printk(KERN_INFO MOD "kallsyms_lookup not found!\n");
        goto err;
    }
    symbol_name = (symbol_name_t)kallsyms_lookup_name("lookup_symbol_name");
    if(!symbol_name) {
        printk(KERN_INFO MOD "lookup_symbol_name not found!\n");
        goto err;
    }
    
    return 0;
    
err:
    remove_proc_entry("procdetails", NULL);
    return -ENODEV;

}

// ----------------------------------------------------------------------------------------------------------
static void __exit procdetails_exit(void)
{
    remove_proc_entry("procdetails", NULL);
        
    printk(KERN_INFO MOD "module end\n");
}


module_init(procdetails_init);
module_exit(procdetails_exit);
MODULE_LICENSE("GPL");
