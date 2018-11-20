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
#ifndef __FLAG_OPEN
#define __FLAG_OPEN 1
#endif

#ifndef __FLAG_SEND
#define __FLAG_SEND 2
#endif

#ifndef __FLAG_RECV
#define __FLAG_RECV 4
#endif

#ifndef __MAX_MAILBOXID_LENGTH
#define __MAX_MAILBOXID_LENGTH 15
#endif

#ifndef __MAX_READERS_WRITER
#define __MAX_READERS_WRITER 5 //max: 4 readers, 1 writer
#endif

#ifndef __MAX_MSG_SIZE
#define __MAX_MSG_SIZE 1024
#endif
/* Userspace function prototypes w/ wrapper */


/* ourmb_open() will be called by both sender (reader) and receiver (writer).
 * The sender process MUST call ourmb_open() FIRST (BEFORE receiver).
 * First successful call wll allocate memory for mailbox in kernel space,
 *      enter process into access list.
 * Input args:
 * const char * mailboxID - Unique mailbox identifier
 * pid_t procID - Process ID of the calling process
 * int lineLen - Number of characters per line that will be read
 * int flag - Identifies what the calling proccess is attempting to do
 */
static int ourmb_open(const char * mailboxID, pid_t procID, int lineLen,  int flag)
{
	return syscall(__NR_ourmb_open, mailboxID, procID, lineLen, flag);
}

/* ourmb_clos() will be called by both sender (reader) and receiver (writer).
 * The receiver process MUST call ourmb_clos() LAST (AFTER sender).
 * Last successful call will deallocate memory for mailbox in kernel space,
 *      remove (last & only) process from access list.
 * Input args:
 * const char * mailboxID - Unique mailbox identifier
 * pid_t procID - Process ID of the calling process
 */
static int ourmb_clos(const char * mailboxID, pid_t procID)
{
	return syscall(__NR_ourmb_clos, mailboxID, procID);
}

/* utilizes copy_from_user()
 * ourmb_send() will be callled from sending (reader) process only
 * Input args:
 * const char * mailboxID - Unique mailbox identifier
 * pid_t procID - Process ID of the calling process
 * char * sendBuff - Pointer the the data to be sent from userspace to kernel space
 * size_t sizeOfSendBuff - Number of bytes allocated for sendBuff (capacity)
 */
 static int ourmb_send(const char * mailboxID, pid_t procID, char * sendBuff, size_t sizeOfSendBuff) 
{
	return syscall(__NR_ourmb_send, mailboxID, procID, sendBuff, sizeOfSendBuff);
}

/* utilizes copy_to_user()
 * ourmb_recv will be called from recieving (writing) process only 
 * Receiver gets pushed data from kernel
 * Input args:
 * const char * mailboxID - Unique mailbox identifier
 * pid_t procID - Process ID of the calling process
 * char * recvBuff - Pointer to the destination of the data to be sent from kernel space
 */ 
static int ourmb_recv(const char * mailboxID, pid_t procID, char * recvBuff)
{
	return syscall(__NR_ourmb_recv, mailboxID, procID, recvBuff);
}


#endif /* end ourmb_user_only.h */


