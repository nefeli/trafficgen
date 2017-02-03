# Traffic Generator
A minimal traffic generator.

## Dependencies
+ [Intel DPDK](http://dpdk.org)
+ libprotobuf-c
+ libpcap

## Installation
Just run `make all`. Alternatively, setup DPDK yourself, just make sure to set
`CONFIG_RTE_BUILD_COMBINE_LIBS=y`.

## Setting up DPDK
First, setup hugepages per: http://dpdk.org/doc/guides/linux_gsg/sys_reqs.html

Then, you'll need to bind any NICs you want to use to dpdk. You can find them
using `/path/to/dpdk/tools/dpdk_nic_bind.py --status`.

Load the uio kernel module and insert the dpdk igb_uio module with
`modprobe uio &&  insmod /path/to/dpdk/target/kmod/igb_uio.ko`.

With that all done, bind each of your desired nics to DPDK with
`/path/to/dpdk/tools/dpdk_nic_bind.py -b igb_uio YOUR_NIC`

## Usage
Start things up with `./bin/pktgen [EAL options] -- LISTEN_PORT`

The only EAL flag you'll really need to tweak is the core mask `-c`. Set it so
there is one more core than the number of ports you plan to use.

To control traffic and see how scripting works, see `controller/example.py`
More detailed documentation coming soon.

## Contributing
Install `clang-format` and run `make format` before submitting a pull request.
