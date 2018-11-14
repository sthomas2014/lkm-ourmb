#include <sys/syscall.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

// Following convention
#ifndef _OURMB_USER_H
#define _OURMB_USER_H 1


// NR: short for NumbeR
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

#ifndef __KERNBUFF_MAX_BYTES
#define __KERNBUFF_MAX_BYTES 4096
#endif


/* Userspace function prototypes w/ wrapper */


// ourmb_open() will be called by both sender (reader) and receiver (writer).
// The sender process MUST call ourmb_open() FIRST (BEFORE receiver).
// First successful call wll allocate memory for mailbox in kernel space,
//      enter process into access list. 
static int ourmb_open(const char * mailboxID, pid_t procID, int kernBuffCapacity,  int flag)
{
	return syscall(__NR_ourmb_open, mailboxID, procID, kernBuffCapacity, flag);
}

// ourmb_clos() will be called by both sender (reader) and receiver (writer).
// The receiver process MUST call ourmb_clos() LAST (AFTER sender).
// Last successful call will deallocate memory for mailbox in kernel space,
//      remove (last & only) process from access list.
static int ourmb_clos(const char * mailboxID, pid_t procID)
{
	return syscall(__NR_ourmb_recv, mailboxID, procID);
}

// utilizes copy_from_user()
// ourmb_send() will be callled from sending (reader) process only
// Sender sends a struct containing a pointer to the "chunked" data
//      and the number of entries and number of bytes
static int ourmb_send(const char * mailboxID, pid_t procID, char * kernBuff, char * sendBuff, int sizeOfSendBuff) 
{
	return syscall(__NR_ourmb_clos, mailboxID, procID, kernBuff, sendBuff, sizeOfSendBuff);
}

// utilizes copy_to_user()
// ourmb_recv will be called from recieving (writing) process only
// Receiver gets pushed data from kernel
static int ourmb_recv(const char * mailboxID, pid_t procID, char * recvBuff, char * kernBuff)
{
	return syscall(__NR_ourmb_send, mailboxID, procID, recvBuff, kernBuff);
}


#endif /* end ourmb_user_only.h */


