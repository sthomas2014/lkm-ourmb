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

#include "/home/scott/Desktop/lkm-ourmb/ourmb_user.h"

/*
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
*/

int main(void)
{
    FILE *input  = fopen("/home/scott/Desktop/lkm-ourmb/test/input.txt", "r"); // input fd
    FILE *output = fopen("output.txt", "w");   // output fd
    if (input == NULL || output == NULL) {
        printf("fopen failed\n");
        exit(-1);
    }
    
    const char * mailboxID = "MAILBOX_1";
    pid_t procID = getpid();
    
    int lineLen = 100;  // Max number of characters to be read per line.
                        // Excess of this amount gets truncated.
    int linesRead = 0;
    
    size_t sizeOfSendBuff = __KERNBUFF_MAX_BYTES; //4096 bytes
    size_t sizeOfRecvBuff = __KERNBUFF_MAX_BYTES; //4096 bytes
    
    char * sendBuff = malloc(sizeOfSendBuff);
    char * recvBuff = malloc(sizeOfRecvBuff);    
    //void * kernBuff = malloc(__KERNBUFF_MAX_BYTES); //4096 bytes == 1 pagesize for x86
    
    // 1st sender process
    // create mailbox in kernel space & register sender on access list
    ourmb_open(mailboxID, procID, lineLen, __FLAG_OPEN | __FLAG_SEND);
    
    // 1st receiver process
    // register receiver on access list for specified mailbox
    ourmb_open(mailboxID, procID + 1, lineLen, __FLAG_RECV);
    
    // Need to make read function defined in header file.
    // To support large amount of data transfer, need to be able to handle
    // WHen size of data is larger than size of send buff. OR just use getline?
    // Would need to save postion in file where ran out of room, copy to 
    // the send buff
    while (fgets(sendBuff, lineLen, input) != NULL)
    {
        linesRead++;
        ourmb_send(mailboxID, procID, sendBuff, lineLen);
        ourmb_recv(mailboxID, procID, recvBuff);
        printf("From kernelspace: %s\n", recvBuff);
        fprintf(output, "%s\n", recvBuff); 
    }
    
    printf("Number of lines read %i\n", linesRead);
	
        
    //
	//ourmb_recv(mailboxID, procID, recvBuff);
    
    // Deallocate, close MAILBOX_1
    ourmb_clos(mailboxID, procID);
    
    // Deallocate userspace buffers
    free(sendBuff);
    free(recvBuff);
    
    // close open files
    fclose(input);
    fclose(output);
        
	return 0;
}
