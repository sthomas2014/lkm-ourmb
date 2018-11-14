/*
** File: ourmb.c for lkm_syscall 
** 
** Original file: syscall.c for lkm_syscall
**
** Originally made by xsyann
** Contact <contact@xsyann.com>
**
** Previous version built by Yuan Xiao
** Contact <xiao.465@osu.edu>
**
** Previous version + 1 built by Yann KOETH
* 
*  Current version built by Scott, Quinn, Andrew
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/stat.h>
#include <linux/slab.h>

// Macro prefix __NR short for : NumbeR
// Macros for ourmb_ system calls
#ifndef __NR_ourmb_open
#define __NR_ourmb_open __NR_nfsservctl
#endif

#ifndef __NR_ourmb_clos
#define __NR_ourmb_clos __NR_getpmsg
#endif

#ifndef __NR_ourmb_send
#define __NR_ourmb_send __NR_putpmsg
#endif

#ifndef __NR_ourmb_recv
#define __NR_ourmb_recv __NR_afs_syscall
#endif

#ifndef SYS_CALL_TABLE
#define SYS_CALL_TABLE "sys_call_table"
#endif

// For use with kmalloc()
// 4096 bytes is size of a kernel page
// Higher risk of segmentation fault..
// if using malloc to allocate mem > 1 page
#ifndef __KERNBUFF_MAX_BYTES
#define __KERNBUFF_MAX_BYTES 4096
#endif


// Loadable kernel module info
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Scott,Andrew,Quinn");
MODULE_DESCRIPTION("Loadable Kernel Module: ourmb");
MODULE_VERSION("0.1");


// Address of syscall table
static ulong *syscall_table = NULL;

// 4 vars to hold original sys_call_table entries[180-184]
static void *original_syscall180 = NULL;
static void *original_syscall181 = NULL;
static void *original_syscall182 = NULL;
static void *original_syscall183 = NULL;

// kernel buffer prototype to hold userspace data
static char * kernBuff;

// Function prototypes
static unsigned long ourmb_open(const char * mailboxID, int kernBuffCapacity, pid_t procID, int flag);

static unsigned long ourmb_clos(const char * mailboxID, pid_t procID);

static unsigned long ourmb_send(const char * mailboxID, pid_t procID, char * kernBuff, char * sendBuff, int sizeOfSendBuff);

static unsigned long ourmb_recv(const char * mailboxID, pid_t procID, char * recvBuff, char * kernBuff);


/******************   Custom system call implementations   ******************/

static unsigned long ourmb_open(const char * mailboxID, int kernBuffCapacity, pid_t procID, int flag)
{
    
	printk(KERN_INFO "Userspace call to ourq_open() succeded!\n");
	printk(KERN_INFO "Params passed are:\nmailboxID: %p\nkernBuffCapacity: %i\n procID: %i\n flag: %i\n", mailboxID, kernBuffCapacity, procID, flag);
	return 0;
}

static unsigned long ourmb_clos(const char * mailboxID, pid_t procID)
{
	printk(KERN_INFO "Userspace call to ourq_clos() succeded!\n");
	return 0;
}

static unsigned long ourmb_send(const char * mailboxID, pid_t procID, char * kernBuff, char * sendBuff, int sizeOfSendBuff)
{
	printk(KERN_INFO "Userspace call to ourq_send() succeded!\n");
	return 0;
}

static unsigned long ourmb_recv(const char * mailboxID, pid_t procID, char * recvBuff, char * kernBuff)
{
	printk(KERN_INFO "Userspace call to ourq_recv() succeded!\n");
	return 0;
}
/************************************************************************/


/******************   System call table manipulations   ******************/
static int is_syscall_table(ulong *p)
{	//Function checks that p == the correct addr of the sys call
        return ((p != NULL) && (p[__NR_close] == (ulong)sys_close));
}

static int page_read_write(ulong address) 
{	//set permission of sys_call_table to rw
	//used to write over 2 unused system called
        uint level;
        pte_t *pte = lookup_address(address, &level);

        if(pte->pte &~ _PAGE_RW)
                pte->pte |= _PAGE_RW;
        return 0;
}

static int page_read_only(ulong address)
{	//restore permission of sys_call_table to read only
        uint level;
        pte_t *pte = lookup_address(address, &level);
        pte->pte = pte->pte &~ _PAGE_RW;
        return 0;
}

/*
** replace_syscall() 
** inputs   : ulong offset - system_call_table entry number to be replaced
** 	        : func_address - address of implementation of custom system call
**	                  aka address of the implementing function()
**          : original_syscall - saves original entry in system call table
**			      before hijacking 
*/
static void hijack_syscall(ulong offset, ulong func_address, ulong * original_syscall)
{
	//Get address of system call table
        syscall_table = (ulong *)kallsyms_lookup_name(SYS_CALL_TABLE); 
        if (is_syscall_table(syscall_table)) {
		//print table address, only pre-first-hijack
                if (offset == __NR_nfsservctl) {
                        printk(KERN_INFO "Syscall table address : %p\n", syscall_table);
                }
		//modify sys_call_table permission to rw                
                page_read_write((ulong)syscall_table);
		//save original entry
                original_syscall = (void *)(syscall_table[offset]);
                printk(KERN_INFO "Original syscall at offset %lu : address : %p\n", offset, original_syscall);
        //replace entry with our custom system call function address
                syscall_table[offset] = func_address;
                printk(KERN_INFO "Syscall #%lu hijacked\n", offset);
                printk(KERN_INFO "New syscall at offset %lu : address : %p\n", offset, (void *)syscall_table[offset]);
		//permission from rw -> ro 
                page_read_only((ulong)syscall_table);
        } 
}
/*************************************************************************/

/******************   LKM Module initialization and cleanup   ******************/

static int init_syscalls(void)
{	//Hijack 4 unimplemented system calls
        printk(KERN_INFO "Module loading: Syscalls being hijacked...\n");
        hijack_syscall(__NR_ourmb_open, (ulong)ourmb_open, original_syscall180);
        hijack_syscall(__NR_ourmb_clos, (ulong)ourmb_clos, original_syscall181);
        hijack_syscall(__NR_ourmb_send, (ulong)ourmb_send, original_syscall182);
        hijack_syscall(__NR_ourmb_recv, (ulong)ourmb_recv, original_syscall183);
        printk(KERN_INFO "Module loaded: Syscalls successfully hijacked\n");
        kernBuff = kmalloc (__KERNBUFF_MAX_BYTES, GFP_ATOMIC);
        return 0;
}

static void cleanup_syscalls(void)
{	printk(KERN_INFO "Module unloading: Syscalls being restored...\n");
    //permission from ro -> rw
        page_read_write((ulong)syscall_table);
	//restore original entries
        syscall_table[__NR_ourmb_open] = (ulong)original_syscall180;
        syscall_table[__NR_ourmb_clos] = (ulong)original_syscall181;
        syscall_table[__NR_ourmb_send] = (ulong)original_syscall182;
        syscall_table[__NR_ourmb_recv] = (ulong)original_syscall183;
	//permission from rw -> ro 
        page_read_only((ulong)syscall_table);
        printk(KERN_INFO "Module unloaded: Syscalls restored successfully\n");
        kfree(kernBuff);
}

module_init(init_syscalls);
module_exit(cleanup_syscalls);

/******************************************************************************/

