#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/rwlock.h>

#define MOD "[proc-owner]: "

int (*xlate)(const char *name, struct proc_dir_entry **ret, const char **residual);
struct proc_dir_entry* (*subdir_find)(struct proc_dir_entry *dir, const char *name, unsigned int len);
void* subdir_lock;
const char *(*syms_lookup)(unsigned long addr, unsigned long *symbolsize, unsigned long *offset, char **modname, char *namebuf);
int (*symbol_name)(unsigned long addr, char *symname);

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
static void get_owner(const char* fname) {
    int rv;
    unsigned int len;
    unsigned long symbolsize, offset;
    const char* fn = fname;
    char* modname = NULL, tmpstr;
    char namebuf[128];
    struct proc_dir_entry *de = NULL;
    
    spin_lock(subdir_lock);
    rv = xlate(fname, &de, &fn);
    printk(KERN_INFO MOD "Ret: %d, Residual: %s\n", rv, fn);
    if(rv != 0) {
        spin_unlock(subdir_lock);
        return;
    }
    len = strlen(fn);
    de = subdir_find(de, fn, len);
    if(de) {
        printk(KERN_INFO MOD "Name: %s, proc fops: %p\n", de->name, de->proc_fops);
        tmpstr = syms_lookup((size_t)(de->proc_fops), &symbolsize, &offset, &modname, namebuf);
        printk(KERN_INFO MOD "Modname: %s\n", modname);
        symbol_name((size_t)(de->proc_fops), namebuf);
        printk(KERN_INFO MOD "Symbol: %s\n", namebuf);
    }
    spin_unlock(subdir_lock);

}


// ----------------------------------------------------------------------------------------------------------
static int proc_read(struct seq_file *m, void *v) {
    seq_printf(m, "test\n");
    get_owner("kallsyms");

    return 0;
}

// ----------------------------------------------------------------------------------------------------------
static int pm_open(struct inode *i, struct file *f) {
    return single_open(f, proc_read, NULL);
}

// ----------------------------------------------------------------------------------------------------------
static const struct file_operations temp_proc_fops = {
  .owner = THIS_MODULE,
  .open = pm_open,
  .read = seq_read,
  .release = single_release,
};

// ----------------------------------------------------------------------------------------------------------
static int __init procowner_init(void)
{
        printk(KERN_INFO MOD "module start\n");
        proc_create("procowner", 0, NULL, &temp_proc_fops);
        
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
        remove_proc_entry("procowner", NULL);
        
        printk(KERN_INFO MOD "module end\n");
}


module_init(procowner_init);
module_exit(procowner_exit);
MODULE_LICENSE("GPL");
