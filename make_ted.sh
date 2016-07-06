#!/bin/bash


export ARCH=arm
export SUBARCH=arm
export CROSS_COMPILE=arm-eabi-

if [ -z "$1" -o "$1" != "env" ] ; then

	make hammerhead_defconfig_ted

	make -j3
fi

