/*
** File: ourmb.c for lkm_syscall 
** 
** Original file: syscall.c for lkm_syscall
**
** Originally made by xsyann (Yann KOETH)
** Contact <contact@xsyann.com>
**
** Previous version built by Yuan Xiao
** Contact <xiao.465@osu.edu>
**
** Current version built by Scott, Quinn, Andrew
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/kfifo.h>
#include <linux/string.h>
#include <linux/spinlock.h>


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


#ifndef __FLAG_OPEN_SEND
#define __FLAG_OPEN_SEND 1
#endif

#ifndef __FLAG_OPEN_RECV
#define __FLAG_OPEN_RECV 2
#endif

#ifndef __FLAG_SEND
#define __FLAG_SEND 4
#endif

#ifndef __FLAG_RECV
#define __FLAG_RECV 8
#endif

// Maximums
#ifndef __MAX_MAILBOXID_LENGTH
#define __MAX_MAILBOXID_LENGTH 15
#endif

// Will support upto 10
// seperate mailboxes
#ifndef __MAX_NUM_MAILBOXES
#define __MAX_NUM_MAILBOXES 10
#endif

// 1 mailbox will support upto
#ifndef __MAX_READERS_WRITER
#define __MAX_READERS_WRITER 10
#endif

// For use with kmalloc()
// 4096 bytes is size of one kernel page
// Higher risk of segmentation fault..
// if using malloc to allocate mem > 1 page
#ifndef __KERN_PAGE_SIZE
#define __KERN_PAGE_SIZE 4096
#endif

/*
//For kfifo dynamic allocation
#ifndef DYNAMIC
#define DYNAMIC
#endif
*/

// Loadable kernel module info
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Scott,Andrew,Quinn");
MODULE_DESCRIPTION("Loadable Kernel Module: ourmb");
MODULE_VERSION("0.1");


/******************************** PROTOTYPES *********************************/
// Address of syscall table
static ulong * syscall_table = NULL;

// 4 vars to hold original sys_call_table entries[180-184]
static void * original_syscall180 = NULL;
static void * original_syscall181 = NULL;
static void * original_syscall182 = NULL;
static void * original_syscall183 = NULL;


static spinlock_t ourmbOpenLock;
static spinlock_t ourmbClosLock;
static spinlock_t ourmbSendLock;
static spinlock_t ourmbRecvLock;

static struct kfifo fifoQueues[__MAX_NUM_MAILBOXES];

// kMbAccessList
typedef struct 
{
    pid_t kProcID;
    int kFlagID;
} kMbAccessList; 


// kMailingList
 typedef struct
 {
    char kMailboxID[__MAX_MAILBOXID_LENGTH];
    int kNumReaders; // readers assigned to particular mailbox
    int kNumWriters; // writers assigned to particular mailbox
    kMbAccessList kAccessList[__MAX_READERS_WRITER];
    char kFifoBuff[32];
 } kMailingList; 
 
// mailing list prototype: list of mailboxID's and process access info
static kMailingList mailingList[__MAX_NUM_MAILBOXES]; 

/*//make message struct to replace char *, call KFIFO_INIT() within initialization function
 int i = 0;
 for(i=0;i<__MAX_NUM_MAILBOXES;i++){
    DECLARE_KFIFO(mailingList[i].kFifoBuff,char *,)
 }
*/

// boolean array of open mailbox slots. TRUE == 1 -> open
static int mbSlotsFree[__MAX_NUM_MAILBOXES];

// helper function prototypes
static void dumpData(void);
static void clearMbSlot(int slot); // Called when a mailbox is to be closed
static void initializeAllFields(void);
static void clearMailingListFields(int mbIterator); //
static void initializeMbAccessList(int mbIterator);
static void invalidateProcID(int mbIterator, pid_t procID);
static void garbageMailboxIdCheck(void);
static int findFreeMbSlot(int claim);
static int findMailboxID(const char *);
static int procIDhasValidAccess(int mbIterator, pid_t procID);
static int findNumValidAccess(int mbIterator);
static int findLowestInvalidAccessIndex(int mbIterator);
static int findSendRecvType(int mbIterator, pid_t procID);
static int findAccessIndexOfProcID(int mbIterator, pid_t procID);

// System call function prototypes
static int ourmb_open(const char *, pid_t, int, int); //typeof(pid_t) == int
static int ourmb_clos(const char *, pid_t);
static int ourmb_send(const char *, pid_t, char *, int, int *);
static int ourmb_recv(const char *, pid_t, char *, int *);


/****************** Helper function implementations ******************/
static void dumpData(void)
{
    int i = 0;
    int j = 0;
    printk(KERN_INFO "********************     Begin Data Dump     ********************");
    for(i=0;i<__MAX_NUM_MAILBOXES;i++)
    {
        printk(KERN_INFO "mbSlotsFree[%i]: %i",i,mbSlotsFree[i]);
    }
    for(i=0;i<__MAX_NUM_MAILBOXES;i++)
    {
        printk(KERN_INFO "mailingList[%i]:\tkMailboxID: %s\tkNumReaders: %i\tkNumWriters: %i\tkFifoBuff: %p\n",i,mailingList[i].kMailboxID, mailingList[i].kNumReaders, mailingList[i].kNumWriters, mailingList[i].kFifoBuff);
        for(j=0;j<__MAX_READERS_WRITER;j++)
        {
            printk(KERN_INFO "kAccessList[%i]:\tkProcID: %i\tkFlagID: %i\n",j,mailingList[i].kAccessList[j].kProcID,mailingList[i].kAccessList[j].kFlagID);
        }
    }
    printk(KERN_INFO "********************     End Data Dump     ********************");
}

// returns the lowest free mailbox index (and sets to unfree if claim == 1)
static int findFreeMbSlot(int claim)
{
    int openSlot = -1;
    int i = 0;
    for(; i < __MAX_NUM_MAILBOXES && openSlot < 0; i++)
    {
        if (mbSlotsFree[i])
        {
            openSlot = i;
            if (claim)
            {
                mbSlotsFree[i] = 0;
            }
        }
    }
    return openSlot;
}

static void garbageMailboxIdCheck(void)
{
 int i = 0;
 
 for(i = 0; i < __MAX_NUM_MAILBOXES; i++)
 {
    if(findNumValidAccess(i) == 0)
    {
        clearMailingListFields(i);
        mbSlotsFree[i] = 1;
    }
 }
}

static void clearMbSlot(int slot)
{
    mbSlotsFree[slot] = 1; 
}


// Finds given string: mailboxID, within mailingList,
// return index of mailboxSlot if found, returns -1 otw
static int findMailboxID(const char * mailboxID)
{
    int found = -1;
    int i = 0;
    for (i = 0;i < __MAX_NUM_MAILBOXES && found < 0; i++)
    {
        if(strlen(mailboxID) == strlen(mailingList[i].kMailboxID))
        {
            if(strncmp(mailboxID, mailingList[i].kMailboxID, strlen(mailboxID)) == 0)
            {
                found = i;
            }                
        }
    }
    return found;
}

// Returns boolean true if given procID is found on kAccessList for a particular mailbox
static int procIDhasValidAccess(int mbIterator, pid_t procID)
{
    int valid = 0;
    int index = findAccessIndexOfProcID(mbIterator, procID);
    if (index > -1)
    {
        valid = 1;
    }
    return valid;
}

// Returns the current total number of processes subscribed to particular mailbox
static int findNumValidAccess(int mbIterator)
{
    int numValid = 0;
    int i = 0;
    for (i = 0; i < __MAX_READERS_WRITER; i++)
    {
        numValid += (mailingList[mbIterator].kAccessList[i].kProcID != -1);        
    }
    return numValid;
}

// Returns the lowest open index in kAccessList for a particular mailbox
static int findLowestInvalidAccessIndex(int mbIterator)
{
    int lowestIndex = -1;
    int i = 0;
    for (i = 0; i < __MAX_READERS_WRITER && lowestIndex < 0; i++)
    {
        if(mailingList[mbIterator].kAccessList[i].kProcID == -1)
        {
            lowestIndex = i;
        }
    }
    return lowestIndex;  
}

// Only called once at module initialization
// WIPES EVERYTHING
static void initializeAllFields(void)
{
    int i = 0;
    int j = 0;
    for(i = 0; i < __MAX_NUM_MAILBOXES; i++)
    {     
        for(j = 0; j < __MAX_READERS_WRITER; j++)
        {
            mailingList[i].kAccessList[j].kProcID = -1;
            mailingList[i].kAccessList[j].kFlagID = -1;    
        }
        mailingList[i].kMailboxID[0] = '\0';
        mailingList[i].kNumReaders = -1;
        mailingList[i].kNumWriters = -1;
        //kfifo_reset(mailingList[j].kFifo);
        clearMbSlot(i);
    }
}

// Called when mailbox is to be closed
static void clearMailingListFields(int mbIterator)
{
    int i = 0;
    for(i = 0; i < __MAX_READERS_WRITER; i++)
    {
        mailingList[mbIterator].kAccessList[i].kProcID = -1;
        mailingList[mbIterator].kAccessList[i].kFlagID = -1;    
    }
    mailingList[mbIterator].kMailboxID[0] = '\0';
    printk (KERN_INFO "After clearing mailboxID: %s",mailingList[mbIterator].kMailboxID);
    mailingList[mbIterator].kNumReaders = -1;
    mailingList[mbIterator].kNumWriters = -1;
    //kfifo_reset(mailingList[mbIterator].kFifo);
    //clearMbSlot(mbIterator);
}

// Called when mailbox is to be opened
static void initializeMbAccessList(int mbIterator)
{
   int i = 0;
    for(i = 0; i < __MAX_READERS_WRITER; i++)
    {
        mailingList[mbIterator].kAccessList[i].kProcID = -1;
        mailingList[mbIterator].kAccessList[i].kFlagID = -1;    
    }    
}

// Called when a process wishes to unsubscribe from mailbox
// decrements r/w count
static void invalidateProcID(int mbIterator, pid_t procID)
{
    int index = findAccessIndexOfProcID(mbIterator, procID);
    
    if (index > -1)
    {
        
        if(mailingList[mbIterator].kAccessList[index].kFlagID == __FLAG_RECV)
        {
            mailingList[mbIterator].kNumWriters -= 1;        
        }
        if(mailingList[mbIterator].kAccessList[index].kFlagID == __FLAG_SEND)
        {
            mailingList[mbIterator].kNumReaders -= 1;
        }
        mailingList[mbIterator].kAccessList[index].kFlagID = -1;
        mailingList[mbIterator].kAccessList[index].kProcID = -1;
    }
}

/*
static int findSendRecvType(int mbIterator, pid_t procID)
{
    int flagType = -1;
    int index = findAccessIndexOfProcID(mbIterator, procID);
    if (index > -1)
    {
        flagType = mailingList[mbIterator].kAccessList[index].kFlagID;
    }
    return flagType;
}
*/

static int findAccessIndexOfProcID(int mbIterator, pid_t procID)
{
    int i = 0;
    int found = -1;
    for(; i < __MAX_READERS_WRITER && found < 0; i++)
    {
        if(mailingList[mbIterator].kAccessList[i].kProcID == procID)
        {
            found = 1;
        }  
    }
    return found;   
}

/******************   Custom system call implementations   ******************/

static int ourmb_open(const char * mailboxID, pid_t procID, int lineLen, int flagID)
{ 
    spin_lock(&ourmbOpenLock);
    if(strlen(mailboxID) > __MAX_MAILBOXID_LENGTH)
    {
        spin_unlock(&ourmbOpenLock);
        return -1;
    }
    
    garbageMailboxIdCheck();
    
     // Case when:
    // 1. Calling process is a sender/receiver and wants to open a new mailbox. Indicated by flagID
    // 2. The mailboxID provided is not already on the mailingList[i].mailboxID
    if((flagID == __FLAG_OPEN_SEND) || (flagID == __FLAG_OPEN_RECV))
    {   
        printk(KERN_INFO "In ourmb_open: passed flag open check.\n");
        //handles 1st sender/receiver
        int localMailboxIterator = findMailboxID(mailboxID);
        int openSlot = findFreeMbSlot(1); //(1) selects option to claim slot if open
        printk(KERN_INFO "In ourmb_open: parameters for (mailboxID DNE exist) and (is free slot)\nlocalMailboxIterator: %i\nopenSlot: %i\nmailboxID: %s\nprocID: %i",localMailboxIterator,openSlot,mailboxID,procID);
        if( localMailboxIterator < 0 && openSlot > -1)
        {
            //Initialize info in mailing list for this mailbox
            initializeMbAccessList(openSlot);
            clearMailingListFields(openSlot);
            //mailingList[openSlot].kFifoBuff = kmalloc(__KERN_PAGE_SIZE, GFP_KERNEL);
            if(mailingList[openSlot].kFifoBuff == NULL)
            {
                printk(KERN_ERR "In ourmb_open: kmalloc() failed.\n");
                spin_unlock(&ourmbOpenLock);
                return -1;
            }
            
            //DECLARE_KFIFO((*fifoQueues)[openSlot], unsigned char, __KERN_PAGE_SIZE/lineLen);            
            //kfifo_init(fifoQueues[openSlot],mailingList[openSlot].kFifoBuff,__KERN_PAGE_SIZE);
            
            //mailingList[openSlot].kFifo = temp
            // Cannot direclty assign string in c
            strncpy( mailingList[openSlot].kMailboxID, mailboxID, strlen(mailboxID));
            if(flagID == (__FLAG_OPEN_SEND))
            {
                mailingList[openSlot].kNumReaders = 1;
                mailingList[openSlot].kNumWriters = 0;
                mailingList[openSlot].kAccessList[0].kFlagID = __FLAG_SEND;
            }
            else if(flagID == (__FLAG_OPEN_RECV))
            {
                mailingList[openSlot].kNumReaders = 0;
                mailingList[openSlot].kNumWriters = 1;
                mailingList[openSlot].kAccessList[0].kFlagID = __FLAG_RECV;
            }
            mailingList[openSlot].kAccessList[0].kProcID = procID;
            
        } else 
        {
            printk(KERN_ERR "Failed check in ourmb_open(). 1st if check that handles open flag");
            printk(KERN_ERR "Mailbox ID: %s already taken or max number of mailboxes are open!\n",mailboxID);
            printk(KERN_ERR "dumpData called within ourmb_open");
            dumpData();
            spin_unlock(&ourmbOpenLock);
            return -1; //Returns -1 on error
        }
    }
    
    // Below if() will be executed given:
    // 1. Calling process is a receiver wants to be added to mailingList. Indicated by flagID
    // 2. The mailboxID provided is already on the mailingList
   else if(flagID == __FLAG_RECV) 
   {   
        //Handles receiver
        int localMailboxIterator = findMailboxID(mailboxID);
        int lowestkAccessIndex = findLowestInvalidAccessIndex(localMailboxIterator);
        printk(KERN_INFO "In ourmb_open: parameters for (mailboxID exists) and(no writers yet)\nlocalMailboxIterator: %i\nmailboxID: %s\nprocID: %i\n",localMailboxIterator,mailboxID,procID);
        if( localMailboxIterator > -1 && mailingList[localMailboxIterator].kNumWriters < 1 && lowestkAccessIndex > -1)
        { 
            //Mailbox is open && writer not subscribed
            //Subscribe receiver to accessList
            mailingList[localMailboxIterator].kNumWriters += 1; //Add receiver to count
            mailingList[localMailboxIterator].kAccessList[lowestkAccessIndex].kProcID = procID;
            mailingList[localMailboxIterator].kAccessList[lowestkAccessIndex].kFlagID = flagID;
            
        } else
        {
            printk(KERN_ERR "Failed check in ourmb_open(). 2nd if check that handles recv flag");
            printk(KERN_ERR "Mailbox ID: %s DNE or max num writers already",mailboxID);
            printk(KERN_ERR "dumpData called within ourmb_open");
            dumpData();
            spin_unlock(&ourmbOpenLock);
            
            return -1; //Returns -1 on error
        }
    }
    
    // Below if() will be executed given:
    // 1. Calling process is a sender wants to be added to mailingList. Indicated by flagID
    // 2. The mailboxID provided is already on the mailingList
   else if(flagID == __FLAG_SEND) 
   { //Handles receiver
        int localMailboxIterator = findMailboxID(mailboxID);
        int lowestkAccessIndex = findLowestInvalidAccessIndex(localMailboxIterator);
        if( (localMailboxIterator > -1 && mailingList[localMailboxIterator].kNumReaders < __MAX_READERS_WRITER - 1 && lowestkAccessIndex > -1) )
        { 
            //Mailbox is open && num readers < 9
            //Subscribe receiver to accessList
            mailingList[localMailboxIterator].kNumReaders += 1; //Add reader to count
            mailingList[localMailboxIterator].kAccessList[lowestkAccessIndex].kProcID = procID;
            mailingList[localMailboxIterator].kAccessList[lowestkAccessIndex].kFlagID = flagID;
        } else
        {
            printk(KERN_ERR "Failed check in ourmb_open(). 3rd if check that handles send flag");
            printk(KERN_ERR "Mailbox ID: %s DNE or max num of readers already",mailboxID);
            printk(KERN_ERR "dumpData called within ourmb_open");
            dumpData();
            spin_unlock(&ourmbOpenLock);
            return -1; //Returns -1 on error
        }
    
    }
    
    spin_unlock(&ourmbOpenLock);
    return 0; //Success  
}

static int ourmb_clos(const char * mailboxID, pid_t procID)
{    
    spin_lock(&ourmbClosLock);
    // Cases:
    // 1. process calls to close and IS last in access list, mailboxID will be removed, 
    //      further calls referencing to this mailbox ID will fail.
    // 2. process calls to close and is NOT last in access list, mailboxID preserved, and
    //      process removed from access list.
    printk( KERN_INFO "call to ourmb close (pre-closing):\nmailboxID: %s\nprocID: %i\n",mailboxID,procID);
    dumpData();
    int ret = 0;
    
    int localMailboxIterator = findMailboxID(mailboxID);
    if(localMailboxIterator > -1)
    {
        
        // Case: 1
        if(procIDhasValidAccess(localMailboxIterator, procID) && findNumValidAccess(localMailboxIterator) > 1)
        { 
            invalidateProcID(localMailboxIterator, procID); //also decrements r/w count
        }
        // Case: 2
        else if (procIDhasValidAccess(localMailboxIterator, procID) && findNumValidAccess(localMailboxIterator) == 1)
        {        
            invalidateProcID(localMailboxIterator, procID); //also decrements r/w count
            //kfifo_free(&fifoQueues[localMailboxIterator]);
            clearMailingListFields(localMailboxIterator);           
        }
        
    }    
    else
    {
    
    printk( KERN_ERR "In ourmb_clos: Failed to close mailbox" );
    printk( KERN_ERR "dumpData called within ourmb_clos, else (failure) branch" );
    dumpData();
    ret = -1;
    } 
    spin_unlock(&ourmbClosLock);
    return ret;
}

static int ourmb_send(const char * mailboxID, pid_t procID, char * sendBuff, int lineLen, int * bytesCopied)
{   
    //spin_lock(&ourmbSendLock);
    printk( KERN_INFO "Call to ourmb_send:\n mailboxID: %s\nprocID: %i\nsendBuff: %p\nlineLen: %i\nbytedCopied: %p\n",mailboxID,procID,sendBuff,lineLen,bytesCopied);
    
    int retValSend = 0;
    int localMailboxIterator = findMailboxID(mailboxID);
    if (localMailboxIterator < 0)
    {
        printk( KERN_ERR "In ourmb_send: MailboxId not found" );
        return -1;
    }
    //retValSend = kfifo_from_user(&fifoQueues[localMailboxIterator],sendBuff,lineLen, bytesCopied);
    // Copy from user syntax:
    // copy_from_user ( to (ptr), from (ptr), n (bytes => int) )
    copy_from_user(mailingList[localMailboxIterator].kFifoBuff,sendBuff,lineLen);
	return retValSend; //0 -> Success, other -> failure
}

static int ourmb_recv(const char * mailboxID, pid_t procID, char * recvBuff, int * bytesCopied)
{
    //spin_lock(&ourmbRecvLock);
    printk( KERN_INFO "Call to ourmb_recv:\n mailboxID: %s\nprocID: %i\nrecvBuff: %p\nbytesCopied: %p\n",mailboxID,procID,recvBuff,bytesCopied);
    
    int retValRecv = 0;
    int localMailboxIterator = findMailboxID(mailboxID);
    if (localMailboxIterator < 0)
    {
        printk( KERN_ERR "In ourmb_recv: mailboxId not found" );
        return -1;
    }
    //retValRecv = kfifo_to_user(&fifoQueues[localMailboxIterator],recvBuff,__KERN_PAGE_SIZE, bytesCopied);
    // Copy to user syntax:
    // copy_from_user ( to (ptr), from (ptr), n (bytes => int) )
    copy_to_user ( recvBuff, mailingList[localMailboxIterator].kFifoBuff, 32);    
    //spin_unlock(&ourmbRecvLock);    
	return retValRecv; //Success
}

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
        {
            pte->pte |= _PAGE_RW;
        }
        return 0; //Success
}

static int page_read_only(ulong address)
{	//restore permission of sys_call_table to read only
        uint level;
        pte_t *pte = lookup_address(address, &level);
        pte->pte = pte->pte &~ _PAGE_RW;
        return 0; //Success
}


static void hijack_syscall(ulong offset, ulong func_address, ulong * original_syscall)
{
	//Get address of system call table
        syscall_table = (ulong *)kallsyms_lookup_name(SYS_CALL_TABLE); 
        if (is_syscall_table(syscall_table)) 
        {
		//print table address, only pre-first-hijack
                if (offset == __NR_nfsservctl) 
                {
                    //printk(KERN_INFO "Syscall table address : %p\n", syscall_table);
                }
		//modify sys_call_table permission to rw                
                page_read_write((ulong)syscall_table);
		//save original entry
                original_syscall = (void *)(syscall_table[offset]);
                //printk(KERN_INFO "Original syscall at offset %lu : address : %p\n", offset, original_syscall);
        //replace entry with our custom system call function address
                syscall_table[offset] = func_address;
                //printk(KERN_INFO "Syscall #%lu hijacked\n", offset);
               // printk(KERN_INFO "New syscall at offset %lu : address : %p\n", offset, (void *)syscall_table[offset]);
		//permission from rw -> ro 
                page_read_only((ulong)syscall_table);
        } 
}

/******************   LKM Module initialization and cleanup   ******************/
static int init_syscalls(void)
{	
        spin_lock_init(&ourmbOpenLock);
        spin_lock_init(&ourmbClosLock);
        spin_lock_init(&ourmbSendLock);
        spin_lock_init(&ourmbRecvLock);
        
        //Hijack 4 unimplemented system calls
        //printk(KERN_INFO "Module loading: Syscalls being hijacked...\n");
        hijack_syscall(__NR_ourmb_open, (ulong)ourmb_open, original_syscall180);
        hijack_syscall(__NR_ourmb_clos, (ulong)ourmb_clos, original_syscall181);
        hijack_syscall(__NR_ourmb_send, (ulong)ourmb_send, original_syscall182);
        hijack_syscall(__NR_ourmb_recv, (ulong)ourmb_recv, original_syscall183);
        //printk(KERN_INFO "Module loaded: Syscalls successfully hijacked\n");  
        
    
        initializeAllFields();
        printk(KERN_INFO "dumpData called within init_syscalls");
        dumpData();
       return 0; //Success
}

static void cleanup_syscalls(void)
{	     

        //printk(KERN_INFO "Module unloading: Syscalls being restored...\n");
    //permission from ro -> rw
        page_read_write((ulong)syscall_table);
	//restore original entries
        syscall_table[__NR_ourmb_open] = (ulong)original_syscall180;
        syscall_table[__NR_ourmb_clos] = (ulong)original_syscall181;
        syscall_table[__NR_ourmb_send] = (ulong)original_syscall182;
        syscall_table[__NR_ourmb_recv] = (ulong)original_syscall183;
	//permission from rw -> ro 
        page_read_only((ulong)syscall_table);
        //printk(KERN_INFO "Module unloaded: Syscalls restored successfully\n");
        //kfree(kernBuff);
        
}

module_init(init_syscalls);
module_exit(cleanup_syscalls);

/******************************************************************************/

