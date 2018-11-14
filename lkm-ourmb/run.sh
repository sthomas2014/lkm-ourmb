#!/bin/bash

echo "┌──────────────────────────────┐"
echo "│  Load Kernel Module syscall  │"
echo "└──────────────────────────────┘"
echo "# insmod ourmb.ko"
sudo insmod ./lkm/ourmb.ko
echo ""
echo "┌──────────────────────────────┐"
echo "│           lsmod              │"
echo "└──────────────────────────────┘"
echo "$ lsmod | grep 'ourmb'"
lsmod | grep "ourmb"
echo ""
echo "┌──────────────────────────────┐"
echo "│           Test               │"
echo "└──────────────────────────────┘"
echo "$ ./test $1"
./test/test $1
echo ""
echo "┌──────────────────────────────┐"
echo "│ Unload Kernel Module syscall │"
echo "└──────────────────────────────┘"
echo "# rmmod ourmb"
sudo rmmod ourmb
echo ""
echo "┌──────────────────────────────┐"
echo "│           dmesg              │"
echo "└──────────────────────────────┘"
echo "$ dmesg"
dmesg | tail -n 24
