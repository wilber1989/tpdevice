#!/bin/bash
make clean
export DPATH=$(pwd)
echo -e "\033[37;41m       程序路径=$DPATH         \033[0m"
if [[ -n "$1" ]]; then
	export DEVICENAME=$1
	echo -e "\033[37;41m       设备名=$1         \033[0m"
else
	export DEVICENAME="device"
	echo -e "\033[37;41m    无设备名输入，使用默认设备device    \033[0m"
fi
make
./bin/main