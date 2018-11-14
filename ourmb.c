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
static void * kernBuff;

// flag telling whether kmalloc succeded
static int kmallocWorked = 0;

// Function prototypes
static unsigned long ourmb_open(const char *, pid_t, int, int); //typeof(pid_t) == int

static unsigned long ourmb_clos(const char *, pid_t);

static unsigned long ourmb_send(const char *, pid_t, char *, char *, int);

static unsigned long ourmb_recv(const char *, pid_t, char *, char *);


/******************   Custom system call implementations   ******************/

static unsigned long ourmb_open(const char * mailboxID, pid_t procID, int kernBuffCapacity, int flag)
{
    //Add to log for debugging, to be removed later
	printk(KERN_INFO "Userspace call to ourq_open() succeded!\n");
	printk(KERN_INFO "ourmb_open params received:\n");
    printk(KERN_INFO "mailboxID(ptr): \t%p\n",        &mailboxID);
    printk(KERN_INFO "mailboxID(str): \t%s\n",        mailboxID);
    printk(KERN_INFO "procID(int): \t%i\n",           procID);
	printk(KERN_INFO "kernBuffCapacity(int): \t%i\n", kernBuffCapacity);
    printk(KERN_INFO "flag(int): \t%i\n",             flag);
    return 0;
}

static unsigned long ourmb_clos(const char * mailboxID, pid_t procID)
{
    //Add to log for debugging, to be removed later
	printk(KERN_INFO "Userspace call to ourq_clos() succeded!\n");
	printk(KERN_INFO "ourmb_open params received:\n");
    printk(KERN_INFO "mailboxID(ptr): \t%p\n", &mailboxID);
    printk(KERN_INFO "mailboxID(str): \t%s\n", mailboxID);
    printk(KERN_INFO "procID(int): \t%i\n",    procID);
    return 0;
}

static unsigned long ourmb_send(const char * mailboxID, pid_t procID, char * kernBuff, char * sendBuff, int sizeOfSendBuff)
{   
    //Add to log for debugging, to be removed later
	printk(KERN_INFO "Userspace call to ourq_send() succeded!\n");
    printk(KERN_INFO "ourmb_send params received:\n");
    printk(KERN_INFO "mailboxID(ptr): \t%p\n", &mailboxID);
    printk(KERN_INFO "mailboxID(str): \t%s\n", mailboxID);
    printk(KERN_INFO "procID(int): \t%i\n",    procID);
	printk(KERN_INFO "sendBuff(ptr): \t%p\n",  sendBuff);
    printk(KERN_INFO "sizeOfSendBuff: \t%i\n", sizeOfSendBuff);
	return 0;
}

static unsigned long ourmb_recv(const char * mailboxID, pid_t procID, char * recvBuff, char * kernBuff)
{
	printk(KERN_INFO "Userspace call to ourq_recv() succeded!\n");
    printk(KERN_INFO "ourmb_recv params received:\n");
    printk(KERN_INFO "mailboxID(ptr): \t%p\n", &mailboxID);
    printk(KERN_INFO "mailboxID(str): \t%s\n", mailboxID);
    printk(KERN_INFO "procID(int): \t%i\n",    procID);
	printk(KERN_INFO "recvBuff(ptr): \t%p\n",  recvBuff);
    printk(KERN_INFO "kernBuff(ptr): \t%p\n",  kernBuff);
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
    //kmalloc to be moved to ourmb_open() after initial testing
        kernBuff = kmalloc (__KERNBUFF_MAX_BYTES, GFP_ATOMIC);
        printk(KERN_INFO "Within init_syscalls, kernBuff(ptr): \t%p\n",  &kernBuff);
        printk(KERN_INFO "kmalloc() allocated: %zu bytes of memory\n", ksize(kernBuff));
        kmallocWorked = kernBuff != NULL;
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
    //kfree() to be moved to ourmb_clos() after initial testing    
        if(kmallocWorked){
            kfree(kernBuff);
        }
}

module_init(init_syscalls);
module_exit(cleanup_syscalls);

/******************************************************************************/

