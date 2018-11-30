#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>

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

// Flags for ourmb_open
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

#ifndef __MAX_MAILBOXID_LENGTH
#define __MAX_MAILBOXID_LENGTH 15
#endif

#ifndef __MAX_READERS_WRITER
#define __MAX_READERS_WRITER 5 //max: 4 readers, 1 writer
#endif

/* Userspace function prototypes w/ wrapper */


/* ourmb_open() will be called by both sender (reader) and receiver (writer).
 * The sender process should call ourmb_open() first, although not required
 * First successful call wll allocate memory for mailbox in kernel space,
 *      enter process into access list.
 * Input args:
 * @mailboxID - Unique mailbox identifier
 * @procID - Process ID of the calling process
 * @lineLen - Number of characters per line that will be read
 * @flag - Identifies what the calling proccess is attempting to do
 */
static int ourmb_open(const char * mailboxID, pid_t procID, int lineLen,  int flag)
{
	return syscall(__NR_ourmb_open, mailboxID, procID, lineLen, flag);
}

/* ourmb_clos() will be called by both sender (reader) and receiver (writer).
 * Last subscriber that successful call close the mailbox in kernel space,
 *      remove (last & only) process from access list.
 * Input args:
 * @mailboxID - Unique mailbox identifier
 * @procID - Process ID of the calling process
 */
static int ourmb_clos(const char * mailboxID, pid_t procID)
{
	return syscall(__NR_ourmb_clos, mailboxID, procID);
}

/* 
 * ourmb_send() will be callled from sending (reader) process only
 * Input args:
 * @mailboxID - Unique mailbox identifier
 * @procID - Process ID of the calling process
 * @sendBuff - Pointer the the data to be sent from userspace to kernel space
 * @lineLen - length of the input string
 * @bytesCopied - Pointer to # bytes successfully copied in userspace
 */
 static int ourmb_send(const char * mailboxID, pid_t procID, char * sendBuff, size_t lineLen, int * bytesCopied) 
{
	return syscall(__NR_ourmb_send, mailboxID, procID, sendBuff, lineLen, bytesCopied);
}

/* 
 * ourmb_recv will be called from recieving (writing) process only 
 * Receiver gets pushed data from kernel
 * Input args:
 * @mailboxID - Unique mailbox identifier
 * @procID - Process ID of the calling process
 * @recvBuff - Pointer to the destination of the data to be sent from kernel space
 * @bytesCopied - Pointer to # bytes successfully copied in userspace
 */ 
static int ourmb_recv(const char * mailboxID, pid_t procID, char * recvBuff, int * bytesCopied)
{
	return syscall(__NR_ourmb_recv, mailboxID, procID, recvBuff, bytesCopied);
}


#endif /* end ourmb_user_only.h */


