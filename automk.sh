#!/bin/bash
make clean
export DPATH=$(pwd)
echo -e "\033[37;41m       程序路径=$DPATH         \033[0m"
make
./bin/main
