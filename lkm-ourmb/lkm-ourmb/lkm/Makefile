##
## Makefile for lkm-ourmb
##
## Made by xsyann
## Contact <contact@xsyann.com>
##
## Updated by Scott Thomas
##
## Started on  Wed Mar 26 13:49:00 2014 xsyann
## Last update Sat Nov 10 19:15:46 2018 scott
##

TARGET	= ourmb

obj-m	+= $(TARGET).o

CURRENT = $(shell uname -r)
KDIR	= /lib/modules/$(CURRENT)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
