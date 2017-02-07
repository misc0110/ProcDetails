#ifndef _PROCDETAILS_H_
#define _PROCDETAILS_H_

#define MOD "[proc-details]: "
#define BUF 1024


#define SHOW_FUNCTION(fnc) if(proc_details.fops_##fnc[0]) snprintf(buf, BUF, "%s        .%s = %s,\n", buf, #fnc, proc_details.fops_##fnc);
#define GET_FUNCTION(fnc) if(proc_details.dir_entry->proc_fops && proc_details.dir_entry->proc_fops->fnc) {\
            symbol_name((size_t)(proc_details.dir_entry->proc_fops->fnc), proc_details.fops_##fnc);\
        } else {\
            proc_details.fops_##fnc[0] = 0;\
        }
        
        
struct _proc_details_ {
    char filename[256];
    struct proc_dir_entry *dir_entry;
    char modname[128];
    char fops[128];
    char fops_open[128];
    char fops_release[128];
    char fops_read[128];
    char fops_write[128];
    char fops_llseek[128];
};

typedef int (*xlate_t)(const char *name, struct proc_dir_entry **ret, const char **residual);
typedef struct proc_dir_entry* (*subdir_find_t)(struct proc_dir_entry *dir, const char* name, unsigned int len);
typedef const char *(*syms_lookup_t)(unsigned long addr, unsigned long *symbolsize, unsigned long *offset, char **modname, char *namebuf);
typedef int (*symbol_name_t)(unsigned long addr, char *symname);



#endif

