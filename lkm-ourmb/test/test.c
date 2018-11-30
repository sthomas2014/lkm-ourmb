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

//#include "/home/scott/Desktop/lkm-ourmb/ourmb_user.h"
#include "ourmb_user.h"

/*
// Flags for ourmb_open
#ifndef FLAG_OPEN
#define FLAG_OPEN 1
#endif

#ifndef FLAG_SEND
#define FLAG_SEND 2
#endif

#ifndef FLAG_RECV
#define FLAG_RECV 4
#endif
*/

int main(void)
{
    FILE *input  = fopen("input.txt", "r"); // input fd
    FILE *output = fopen("output.txt", "w");   // output fd
    if (input == NULL || output == NULL) {
        printf("fopen failed\n");
        exit(-1);
    }
    
    const char * mailboxID = "MAILBOX_1";
    pid_t procID = getpid();
    
    int lineLen = 32;  // Max number of characters to be read per line.
                        // Excess of this amount gets truncated.
    int linesRead = 0;
    char * sendBuff;
    char * recvBuff;
    size_t sizeOfSendBuff = __KERNBUFF_MAX_BYTES; //4096 bytes
    size_t sizeOfRecvBuff = __KERNBUFF_MAX_BYTES; //4096 bytes
    
    if((sendBuff = malloc(sizeOfSendBuff)) == NULL){
        printf("malloc for sendBuff failed\n");
        return -1;
    }
    int * bytesCopiedTo = 0;
    if((recvBuff = malloc(sizeOfRecvBuff)) == NULL){
        printf("malloc for recvBuff failed\n");
        return -1;
    }
    int * bytesCopiedFrom = 0;
    
    // ** Subscribe some readers. Verify using 'dmesg' to look at data dump
    // 1st sender process
    // create mailbox in kernel space & register sender on access list    
    if (ourmb_open(mailboxID, procID, lineLen, __FLAG_OPEN_SEND) != 0)
    {
        printf("Error opening mailbox for reader1 (sender) \n");
    }
    // 1st sender process
    // create mailbox in kernel space & register sender on access list    
    if (ourmb_open(mailboxID, procID+1, lineLen, __FLAG_SEND) != 0)
    {
        printf("Error opening mailbox for reader2 (sender) \n");
    }
    // 1st sender process
    // create mailbox in kernel space & register sender on access list    
    if (ourmb_open(mailboxID, procID+2, lineLen, __FLAG_SEND) != 0)
    {
        printf("Error opening mailbox for reader3 (sender) \n");
    }
    // 1st sender process
    // create mailbox in kernel space & register sender on access list    
    if (ourmb_open(mailboxID, procID+3, lineLen, __FLAG_SEND) != 0)
    {
        printf("Error opening mailbox for reader4 (sender) \n");
    }
    
    // ** Attempt to subscribe some writers. Only the 1st one should work, other should fail
    // ** Verify using 'dmesg' to look at data dump
    // 1st receiver process
    // register receiver on access list for specified mailbox
    if (ourmb_open(mailboxID, procID + 4, lineLen, __FLAG_RECV) != 0)
    {
        printf("Error opening mailbox for writer (receiver) \n");
    }
    
    
    while (fgets(sendBuff, lineLen, input) != NULL)
    {
        linesRead++;
        
        printf("To kernelspace: %s\n", sendBuff);
        ourmb_send(mailboxID, procID, sendBuff, lineLen, bytesCopiedTo);
        
        ourmb_recv(mailboxID, procID+4, recvBuff, bytesCopiedFrom);
        printf("From kernelspace: %s\n", recvBuff);
        
        fprintf(output, "%s\n", recvBuff); 
    }
    
    
    
    printf("Number of lines read %i\n", linesRead);
    
    // Deallocate, close MAILBOX_1
    ourmb_clos(mailboxID, procID);
    ourmb_clos(mailboxID, procID+1);
    ourmb_clos(mailboxID, procID+2);
    ourmb_clos(mailboxID, procID+3);
    ourmb_clos(mailboxID, procID+4);
    
    // Deallocate userspace buffers
    free(sendBuff);
    free(recvBuff);
    
    // close open files
    fclose(input);
    fclose(output);
        
	return 0;
}
