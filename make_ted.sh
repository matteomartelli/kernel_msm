#!/bin/bash

export ARCH=arm
export SUBARCH=arm
export CROSS_COMPILE=arm-eabi-

make hammerhead_defconfig_ted

make -j3
