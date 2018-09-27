#!/bin/bash

sudo insmod kernel_module/processor_container.ko
sudo chmod 777 /dev/pcontainer
#./benchmark/benchmark "$@"
#./benchmark/benchmark2 "$@"
./benchmark/benchmark3 "$@"
#./benchmark/benchmark4 "$@"
sudo rmmod processor_container
