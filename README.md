# Traffic Generator
A minimal traffic generator.

## Dependencies
+ [Intel DPDK](http://dpdk.org)
+ libreadline (`libreadline-dev` on debian)

## Installation
```
wget http://dpdk.org/browse/dpdk/snapshot/dpdk-2.2.0.tar.gz
tar xzf dpdk-2.2.0.tar.gz
export RTE_SDK=/path/to/dpdk-2.2.0
export RTE_TARGET=x86_64-native-linuxapp-gcc
cd $RTE_SDK
make install T=$RTE_TARGET

git clone https://github.com/melvinw/pktgen
cd /path/to/pktgen
make
```

## Setting up DPDK
First, setup hugepages per: http://dpdk.org/doc/guides/linux_gsg/sys_reqs.html

Then, you'll need to bind any NICs you want to use to dpdk. You can find them
using `$RTE_SDK/tools/dpdk_nic_bind.py --status`.

Load the uio kernel module and insert the dpdk igb_uio module with
`modprobe uio &&  insmod $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko`.

With that all done, bind each of your desired nics to DPDK with
`$RTE_SDK/tools/dpdk_nic_bind.py -b igb_uio YOUR_NIC`

## Usage
Start things up with `./build/pktgen [EAL options]`

The only EAL flag you'll really need to tweak is the core mask `-c`. Set it so
there is one more core than the number of ports you plan to use.

At the `tgen>` prompt use the following flags to generate traffic:
```
-m M -t T -w W -n N -s MIN[-MAX] [-r] [-l]
Traffic Gen Options and Flags
        -m M          Transmit at M mpbs
        -t T          Generate traffic for T seconds
        -w W          Warmup for W seconds before generating traffic
        -n N          Generate a uniform distribution of N flows
        -s MIN[-MAX]  Genearte packets with sizes in [MIN,MAX] (or only of size MIN if MAX isn't specified)
        -r            Randomize packet payloads
        -l            Measure latency
```
