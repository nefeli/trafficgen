#!/bin/bash

DPDK_DIR=dpdk-2.2.0
RTE_SDK=./$DPDK_DIR
RTE_TARGET=x86_64-native-linuxapp-gcc
if [ ! -d ./$DPDK_DIR ]
then
    wget http://dpdk.org/browse/dpdk/snapshot/dpdk-2.2.0.tar.gz
    tar xzf dpdk-2.2.0.tar.gz
fi

cd ./$DPDK_DIR
cat config/common_linuxapp | sed -E \
    "s/(CONFIG_RTE_BUILD_COMBINE_LIBS)=.*/\1=y/" \
    > pktgen_config
cat pktgen_config > config/common_linuxapp
make -j 8 install T=x86_64-native-linuxapp-gcc

cd ..
make
