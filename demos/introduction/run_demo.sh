#!/bin/bash

SAVED_ASLR=$(cat /proc/sys/kernel/randomize_va_space)

echo 0 | sudo tee /proc/sys/kernel/randomize_va_space &> /dev/null

make &> /dev/null

./introduction 10 &
PID1=$!
./introduction 200 &
PID2=$!

trap 'kill -9 $PID1; kill -9 $PID2' SIGINT
wait $PID1
wait $PID2

echo $SAVED_ASLR | sudo tee /proc/sys/kernel/randomize_va_space &> /dev/null
