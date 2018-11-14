Project for CSE 2431 - Sys 2: Oper Sys: lkm-ourmb
Group members: Scott Thomas, Jiacheng Liu, Quinn Wu
Built on "lkm-syscall-master" originally built by xysann

lkm-syscall-master - Provided the functionality of hijacking an unused system call (184 - tuxcall), and a test unit to show funtionality

Our project: lkm-syscall-mod, is an adaption of the original lkm-syscall-master.
The functionality of the original is extended by hijacking 4 unused system calls (180-183) instead of 1 (184).
The new code introduced adds a method of message passing IPC between n readers and 1 writer process. (i.e. "the reader writer problem")
This is accomplished by the group's implementation of the "ourmb_<....>" system calls and respective API's of the same name:
	
	ourmb_open() //Create a mailbox if not already created, add calling process to access list (condidtionally).
	ourmb_clos() //Remove calling process from access list, destroy the mailbox if process was last on access list
	ourmb_send() //Sender process provides a message to be sent to the kernel space message queue (buffer)
	ourmb_recv() //Receiver process retrieves a message from kernel space message queue (buffer)

These system calls are modeled based off both the System V "msg.." API's  as well as POSIX "mq_..." API's.
The main objective of the group's ourmb API is to focus on being a lightweight form of message passing.
This results in reduced generality, with increased speeds vs. POSIX style message queues (ideally).




