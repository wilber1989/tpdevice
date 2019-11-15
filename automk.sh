#!/bin/bash
make clean
export DPATH=$(pwd)
echo 程序路径=$DPATH
make
cd bin
./main
cd ..