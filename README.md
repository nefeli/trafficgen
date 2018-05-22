# Traffic Generator

A traffic generator built on [BESS](https://github.com/NetSys/bess).

## Setup

Like any other DPDK applications, you need to [set up hugepages](
http://dpdk.org/doc/guides/linux_gsg/sys_reqs.html#reserving-hugepages-for-dpdk-use)
-- by default, BESS requires 2GB per CPU socket. Using 2MB hugepages is
recommended since it can be configured without system reboot and the
performance difference compared to 1GB ones is negligible.

Bind any NICs you want to generate traffic on to DPDK and take note of their PCIe addresses.

Finally, clone this repo and build BESS with the trafficgen plugins. See the
[BESS Wiki](https://github.com/NetSys/bess/wiki/Build-and-Install-BESS) for notes about build dependencies.

```
$ git clone --recursive git@github.com:nefelinetworks/trafficgen.git
$ cd trafficgen
$ pip3 install -r requirements.txt
$ make
```

## Running

After setting things up, generating traffic is simple.

```
$ ./run.py
Type "help" for more information.
Starting BESS...
Done.
Spawning port monitor thread...
localhost:10514 $
```

## Generating Traffic

To generate a simple stream of UDP packets on a single port (03:00.0 for
example) and watch for return traffic, run:

```
localhost:10514 $ start 03:00.0 udp
localhost:10514 $ monitor port 03:00.0
```

Use the following commands to start, stop and monitor traffic:

```
monitor pipeline                                  Monitor packet counters in the datapath pipeline
help                                              List available commands
show config                                       Show the current confiugration of all ports
show config PORT...                               Show the current confiugration of a port
reset                                             Reset trafficgen
monitor port                                      Monitor the current traffic of all ports
monitor port PORT...                              Monitor the current traffic of specified ports
set csv CSV                                       Set the CSV file for stats output
start PORT MODE [TRAFFIC_SPEC...]                 Start sending packets on a port
stop PORT...                                      Stop sending packets on a set of ports
```

See the [advanced guide](AdvancedGuide.md) for how to generate different types
of traffic.

## Summarizing Results

To pretty-print a summary of trafficgen results, run `summarize.py` on the CSV output:

```
cd scripts
./summarize.py <CSV file>
```
