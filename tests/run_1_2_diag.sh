#!/bin/sh
# Quick diagnostic script for task 1.2 testing
rmmod phantom 2>/dev/null
insmod /mnt/phantom/kernel/phantom.ko
sleep 0.2
dmesg -C
echo "=== Running test ==="
/mnt/phantom/tests/test_1_2_vmcs
EC=$?
echo "=== EXIT CODE: $EC ==="
echo "=== DMESG ==="
dmesg
