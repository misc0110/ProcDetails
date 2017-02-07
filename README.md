# ProcDetails
The ProcDetails kernel module shows details about `procfs` files. 
If a proc file is associated with a kernel module, the name of the module is shown. Otherwise, the module can only show that the file is created by the kernel. 
The following other details are shown:

 * `Mode`: The permissions of the file:
 	* `Format`: Bitmask defined in `include/uapi/linux/stat.h`. Regular files are 100. 
 	* `Permissions`: Bitmask defined in `include/uapi/linux/stat.h`.
 * `Count`: Uses of the file
 * `In use`: Number of processes currently using the file.
 * `File Operations`: Shows the name of the file operations struct and all defined functions pointers. 
	

## Usage

    sudo insmod procdetails
    ./procinfo /proc/cpuinfo
    ------------------------------------------------------------
	                        /proc/cpuinfo
    ------------------------------------------------------------
	> Module                                     : Kernel
	> Mode                                      
	      Format                                 : 100
	      Permissions                            : 444
	> Count                                      : 1
	> In use                                     : 0
	> File Operations                            : Yes
	    proc_cpuinfo_operations = {
		.open = cpuinfo_open,
		.read = seq_read,
		.release = seq_release,
		.llseek = seq_lseek,
      };

