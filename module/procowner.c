#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/rwlock.h>
#include <asm/uaccess.h>

#define MOD "[proc-details]: "

static struct {
    char filename[256];
    struct proc_dir_entry *dir_entry;
    char modname[128];
    char fops[128];
    char fops_open[128];
    char fops_release[128];
    char fops_read[128];
    char fops_write[128];
    char fops_llseek[128];
} proc_details;

static int (*xlate)(const char *name, struct proc_dir_entry **ret, const char **residual);
static struct proc_dir_entry* (*subdir_find)(struct proc_dir_entry *dir, const char *name, unsigned int len);
static void* subdir_lock;
static const char *(*syms_lookup)(unsigned long addr, unsigned long *symbolsize, unsigned long *offset, char **modname, char *namebuf);
static int (*symbol_name)(unsigned long addr, char *symname);

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
    atomic_t count;         /* use count */
    atomic_t in_use;        /* number of callers into module in progress; */
                    /* negative -> it's going away RSN */
    struct completion *pde_unload_completion;
    struct list_head pde_openers;   /* who did ->open, but not ->release */
    spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
    u8 namelen;
    char name[];
};

// ----------------------------------------------------------------------------------------------------------
#define BUF 1024
#define SHOW_FUNCTION(fnc) if(proc_details.fops_##fnc[0]) snprintf(buf, BUF, "%s        .%s = %s,\n", buf, #fnc, proc_details.fops_##fnc);
static int proc_procreadwrite_show (struct seq_file *m, void *v) {
    size_t i, spacing;
    char buf[BUF];
    char spacing_left[] = "                                                   ";
    const char* padding = "                                                   ";
    int pad = 45;

    spacing = (60 - strlen(proc_details.filename) - 6) / 2;
    if(spacing < 0 || spacing >= 60) {
        spacing = 0;
    }
    spacing_left[spacing] = 0;

    snprintf(buf, BUF, "------------------------------------------------------------\n%s/proc/%s\n------------------------------------------------------------\n", spacing_left, proc_details.filename);
    
    snprintf(buf, BUF, "%s> %s%*.*s : %s\n", buf, "Module ", pad - 8, pad - 8, padding, proc_details.modname); 
    snprintf(buf, BUF, "%s> %s%*.*s\n", buf, "Mode "); 
    snprintf(buf, BUF, "%s      %s%*.*s : %o\n", buf, "Format ", pad - 12, pad - 12, padding, (proc_details.dir_entry->mode & 0170000) / (8*8*8));
    snprintf(buf, BUF, "%s      %s%*.*s : %o\n", buf, "Permissions ", pad - 17, pad - 17, padding, proc_details.dir_entry->mode & 0777);
    snprintf(buf, BUF, "%s> %s%*.*s : %d\n", buf, "Count ", pad - 7, pad - 7, padding, proc_details.dir_entry->count); 
    snprintf(buf, BUF, "%s> %s%*.*s : %d\n", buf, "In use ", pad - 8, pad - 8, padding, proc_details.dir_entry->in_use); 
    
    snprintf(buf, BUF, "%s> %s%*.*s : %s\n", buf, "File Operations ", pad - 17, pad - 17, padding, proc_details.fops[0] ? "Yes" : "No");
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
#define GET_FUNCTION(fnc) if(proc_details.dir_entry->proc_fops->fnc) {\
            symbol_name((size_t)(proc_details.dir_entry->proc_fops->fnc), proc_details.fops_##fnc);\
        } else {\
            proc_details.fops_##fnc[0] = 0;\
        }
        
static void get_details() {
    int rv;
    unsigned int len;
    unsigned long symbolsize, offset;
    const char* fn = proc_details.filename;
    char *tmpstr, *modname = NULL;
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
        tmpstr = syms_lookup((size_t)(proc_details.dir_entry->proc_fops), &symbolsize, &offset, &modname, namebuf);
        if(modname) {
            strlcpy(proc_details.modname, modname, 128);
        } else {
            strcpy(proc_details.modname, "N/A");
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
static int __init procowner_init(void)
{
    printk(KERN_INFO MOD "module start\n");
    int merr = 0;

    proc_create("procdetails", 0666, NULL, &proc_procreadwrite_operations);
        
    xlate = kallsyms_lookup_name("__xlate_proc_name");   
    if(!xlate) {
        printk(KERN_INFO MOD "__xlate_proc_name not found!\n");
        return -ENODEV;
    }
    subdir_lock = kallsyms_lookup_name("proc_subdir_lock");
    if(!subdir_lock) {
        printk(KERN_INFO MOD "proc_subdir_lock not found!\n");
        return -ENODEV;
    }
    subdir_find = kallsyms_lookup_name("pde_subdir_find");
    if(!subdir_find) {
        printk(KERN_INFO MOD "pde_subdir_find not found!\n");
        return -ENODEV;
    }
    syms_lookup = kallsyms_lookup_name("kallsyms_lookup");
    if(!syms_lookup) {
        printk(KERN_INFO MOD "kallsyms_lookup not found!\n");
        return -ENODEV;
    }
    symbol_name = kallsyms_lookup_name("lookup_symbol_name");
    if(!symbol_name) {
        printk(KERN_INFO MOD "lookup_symbol_name not found!\n");
        return -ENODEV;
    }
    
    return 0;
}

// ----------------------------------------------------------------------------------------------------------
static void __exit procowner_exit(void)
{
    remove_proc_entry("procdetails", NULL);
        
    printk(KERN_INFO MOD "module end\n");
}


module_init(procowner_init);
module_exit(procowner_exit);
MODULE_LICENSE("GPL");
