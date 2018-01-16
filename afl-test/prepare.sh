#!/bin/sh

echo 0 > /proc/sys/kernel/kptr_restrict
echo core > /proc/sys/kernel/core_pattern

cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor

rm /dev/shm/*.synced_queue
