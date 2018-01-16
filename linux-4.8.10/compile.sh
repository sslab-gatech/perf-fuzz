#!/bin/bash

make LOCALVERSION=+ -j16

if [ $? -ne 0 ]; then
	echo "make fail!"
	exit -1
fi

sudo make headers_install && sudo make modules_install

if [ $? -ne 0 ]; then
	echo "install modules fail!"
	exit -1
fi

sudo make install

if [ $? -ne 0 ]; then
	echo "make install fail!"
	exit -1
fi

echo "reboot"
