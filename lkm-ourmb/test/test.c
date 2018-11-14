/*
** test.c for lkm-ourmb
**
** Originally built by xsyann
** Contact <contact@xsyann.com>
**
** Current-1 version built by Yuan Xiao
** Contact <xiao.465@osu.edu>
**
** Current version built by Scott Thomas, Jiacheng Liu, Quinn Wu
*/

#include <sys/syscall.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "/home/scott/Desktop/lkm-ourmb/ourmb_user.h"


int main(int argc, char* argv[])
{
    //simple values for testing
    char line[100];
    const char * mailboxID = "MAILBOX_1";
    int kernBuffCapacity = __KERNBUFF_MAX_BYTES / sizeof(line);
    char * sendBuff = malloc(kernBuffCapacity*sizeof(line));
    char * recvBuff = malloc(kernBuffCapacity*sizeof(line));    
    char * kernBuff = malloc(__KERNBUFF_MAX_BYTES); //4096 bytes == 1 pagesize for x86
    int sizeOfSendBuff = sizeof(sendBuff);
    pid_t procID = getpid();
    int flag = 2;
    
    printf("mailboxID is: %s\n",mailboxID);
    printf("kernBuffCapacity is: %d\n",kernBuffCapacity);
    printf("sizeOfSendBuff is: %d\n", sizeOfSendBuff);

	ourmb_open(mailboxID, procID, kernBuffCapacity, flag);
    
	ourmb_clos(mailboxID, procID);
    
	ourmb_send(mailboxID, procID, kernBuff, sendBuff, sizeOfSendBuff);
    
	ourmb_recv(mailboxID, procID, recvBuff, kernBuff);        
    
    free(sendBuff);
    free(recvBuff);
    free(kernBuff);
        
	return 0;
}
