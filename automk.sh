#!/bin/bash
make clean
make

export DPATH=$(pwd)
echo -e "\033[37;41m     程序路径=$DPATH         \033[0m"
if [[ -n "$1" ]]; then
	export DEVICEID=$1
	echo -e "\033[37;41m     设备ID=$1         \033[0m"
else
	export DEVICEID="device"
	echo -e "\033[37;41m     无设备ID输入，使用默认值：DEVICEID=device    \033[0m"
fi
if [[ -n "$2" ]]; then

	echo -e "\033[37;41m     brokerIP=$2         \033[0m"
else
	echo -e "\033[37;41m     无brokerIP输入，使用默认IP=127.0.0.1    \033[0m"
fi
if [[ -n "$3" ]]; then
	echo -e "\033[37;41m     连接端口=$3         \033[0m"
else
	echo -e "\033[37;41m     无连接端口输入，使用默认端口1883    \033[0m"
fi

./bin/main $2 $3