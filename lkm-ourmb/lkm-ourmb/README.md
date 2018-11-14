Project for CSE 2431 - Sys 2: Operating Systems

Project name: lkm-ourmb

Group members: Scott Thomas, Jiacheng Liu, Quinn Wu

lkm-ourmb builds upon lkm-syscall (originally built by xysann, located on gitHub).

The functionality of the original is extended by hijacking 4 unused system calls (180-183).
The new functionality adds a method of IPC: message passing between n readers and 1 writer process. (i.e. "the reader writer problem")
This is accomplished by the group's implementation of the "ourmb_<....>" system calls and respective API's of the same name.
	
	ourmb_open() //Create a mailbox if not already created, add calling process to access list (condidtionally).
	ourmb_clos() //Remove calling process from access list, destroy the mailbox if process was last on access list.
	ourmb_send() //Sender process provides a message to be sent to the kernel space message queue (buffer).
	ourmb_recv() //Receiver process retrieves a message from kernel space message queue (buffer).

These system calls are modeled based off both the System V "msg.." API's  as well as POSIX "mq_..." API's.
The main objective of the group was to focus on buiding a lightweight message passing mechanism that is able to outperform the POSIX message queue implementation in certain cases.

