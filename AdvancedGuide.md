# Advanced Guide

The command to start traffic takes the follwing form

```
start PORT MODE [OPTIONS...]
```

## Modes

You can generate three types of traffic
+ `udp`: Simple stream(s) of UDP packets
+ `flowgen`: More realistic, flow-based traffic
+ `http`: Like `flowgen` but with HTTP payloads

## Quick Start

Here are a few useful commands to quickly get started. See [Options](#options)
below for more a more detailed configurations.

A simple benchmarking scenario might involve measuring how well a DUT copes with
various amounts of incoming flows. You can generate 10,000 infinitely long-lived
UDP flows containing 60 byte packets with the following command. You can
identify which port to generate traffic on by either its PCI address in
`BUS:SLOT.FUNCTION` format, or by its integral DPDK port id.

```
localhost:10514 $ start 03:00.0 udp num_flows=10000, pkt_size=60
```

You can then check how well the DUT is keeping up by running `monitor port`
which will produce the output below. The `INC` columns indicate the rate of
return traffic from the DUT along with the average, median and 99th
percentile/jitter round-trip times experienced by packets (reported in
microseconds). `monitor port` also dumps a comma separated form of its output
to `/tmp/bench.csv`. You can change where stats get dumped for future runs by
running `set csv <PAHT_TO_YOUR_CSV>`.

```
localhost:10514 $ monitor port
Monitoring ports: 03:00.0 (Send CTRL + c to stop)

14:40:49.469716       INC     Mbps      Mpps   dropped   avg_rtt (us)   med_rtt (us)    99_rtt (us)         avg_jit (us)   med_jit (us)    99_jit (us)         OUT     Mbps      Mpps   dropped
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
03:00.0/PMDPort            10128.9    15.070      3582         15.314         14.650         18.200                0.822          0.650          2.100              10134.5    15.081       143
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
```

Running `show config` will dump the current configuration of all active ports,
including information like MAC addresses, a list of cores used, and other
mode-specific settings:

```
localhost:10514 $ show config
Port 03:00.0
-----------
rfc2544_loss_rate:   disabled
rfc2544_window:             5
rfc2544_warmup:             2
rfc2544_drain:              5
rfc2544_adj:               10
rfc2544_max_rounds:        10
pps:             <= line rate
mbps:            <= line rate
src_mac:    3c:fd:fe:a2:a6:e0
dst_mac:    02:1e:67:9f:4d:bb
src_ip:           192.168.0.1
dst_ip:              10.0.0.1
tx_cores:                   0
rx_cores:                   0
pkt_size:                  60
num_flows:               1000
imix:                disabled
-----------
```

To step generating traffic just enter `stop 03:00.0` at the prompt.

If you're benchmarking a DUT over a fast NIC, you may need to use multiple cores
to saturate the link. You can do that by appending the `cores` option to your
command like so:

```
localhost:10514 $ start 03:00.0 udp num_flows=10000, pkt_size=60, cores="0 1"
```

Run `monitor ports` again and note the higher rates in the `OUT` columns.

```
localhost:10514 $ monitor port
Monitoring ports: 03:00.0 (Send CTRL + c to stop)

14:40:49.469716       INC     Mbps      Mpps   dropped   avg_rtt (us)   med_rtt (us)    99_rtt (us)         OUT     Mbps      Mpps   dropped
---------------------------------------------------------------------------------------------------------------------------------------------
03:00.0/PMDPort            12551.5    18.124    775004         38.612         28.775         65.300               21692.3    32.280       782
---------------------------------------------------------------------------------------------------------------------------------------------
```

## Options 

There are several knobs you can tweak to control traffic. They are specified
like `foo="bar", baz=3`.

### General Options

The following options are applicable to all modes of traffic.

Option | Description
------ | -----------
`pps` | Setting `pps=X` will result in trafficgen sending traffic at `X` packets per second. When set with `rfc2544_loss_rate`, trafficgen will start sending at `X` packets per second before adjusting the sending rate. By default `pps` is not set, meaning trafficgen will try to send at line rate.
`mbps` | Setting `mbps=X` will result in trafficgen sending traffic at `X` megabits per second. By default `mbps` is not set and trafficgen will try to send at line rate.
`tx_cores`, `rx_cores` | Setting `tx_cores` and `rx_cores` will split the work of sending and receiving packets on a port across multiple cores. For example, setting `tx_cores="0 1"` and `rx_cores="2 3"` will result in trafficgen splitting traffic sending packets on cores `0` and `1` and receiving them on cores `2` and `3`. By default `{t,r}x_cores` are not set and trafficgen will send and receive on the same core, chosen at random.
`src_mac`, `dst_mac` | Setting `src_mac=X` and `dst_mac=Y` will result in trafficgen setting the source and destination Ethernet addresses to `X` and `Y` respectively. By default `src_mac` is set to the Ethernet address of the sending port and `dst_port` is set to `02:1e:67:9f:4d:bb`.
`src_ip`, `dst_ip` | Setting `src_ip=X` and `dst_ip=Y` will result in trafficgen generating flows with source and destination IP addresses starting at `X` and `Y` respectively. By default `src_ip` and `dst_ip` are `192.168.0.1` and `10.0.0.1` respectively.
`tx_timestamp_offset`, `rx_timestamp_offset` | The offset in bytes to place and read timestamps for latency measurements. By default `tx_timestamp_offset` and `rx_timestamp_offset` are unset and trafficgen will stamp and read timestamps from the first 8 bytes of the TCP/UDP payload. However, in some cases, when the DUT performs encapsulation or decapsulation or your mode's pipeline uses header options, you may need to change these offsets to see meaningful latency measurements. Setting `{r,t}x_timestamp_offset=N` will result in trafficgen stamping and reading timestamps `N` bytes from the beginning of the packet (e.g., `N=42` will place timestamps at the beginning of a UDP payload. 14 bytes for the Ethernet header, 20 for the IP header and 8 for the UDP header).
`rfc2544_loss_rate` | Setting `rfc2544_loss_rate=X` will result in trafficgen sending traffic at rate such that it sees a frame last rate of `X` (in `[0,1]`) as defined by [RFC2544](https://tools.ietf.org/html/rfc2544#section-26.3). If `rfc2544_loss_rate` is set, `pps` must be set to the initial sending rate. By befault `rfc2544_loss_rate` is not set and trafficgen sends at whatever rate you tell it to.
`rfc2544_window` | Setting `rfc2544_window=X` will result in the RFC 2544 process for this port using `X` second rounds excluding the warmup and draining periods. The default round duration is `30` seconds.
`rfc2544_warmup` | Setting `rfc2544_warmup=X` will result in the RFC 2544 process for this port ignoring the first `X` seconds ,i.e. not take any measurements, for each round. The default is warmup duration is `5` seconds.
`rfc2544_drain` | Setting `rfc2544_drain=X` will result in the RFC 2544 process for this port waiting for `X` seconds for its RX queues to drain before beginning a new round. The default queue drainage duration is `5` seconds.
`rfc2544_adj` | Setting `rfc2544_adj=X` will result in the RFC 2544 process for this port dropping its sending rate by `X`% after any round it experiences more than `loss_rate`% packet loss. After experiencing packet loss <= `loss_rate`% for two consecutive rounds it will increase its sending rate by `X`%.
`rfc2544_max_rounds` | Setting `rfc2544_max_rounds=N` will limit the RFC 2544 process for this port to `N` rounds of searching for the ideal sending rate. The default is `10` rounds.

### UDP Options

The following options are only applicable to ports sending in `udp` mode.

Option | Description
------ | -----------
`num_flows` | Setting `num_flows=N` will result in trafficgen sending `N` flows. By default `num_flows` is set to `10`.
`pkt_size` | Setting `pkt_size=X` will result in trafficgen sending `X`-byte packets. By default `pkt_size` is set to `60`.
`imix` | Setting `imix=1` will result in trafficgen generate [Internet Mix](https://en.wikipedia.org/wiki/Internet_Mix)-like traffic. By default `imix` is not set and trafficgen generates fixed-size packets of `pkt_size` bytes.

### FlowGen Options

The following options are only applicable to ports sending in `flowgen` mode.

Option | Description
------ | -----------
`pkt_size` | Setting `pkt_size=X` will result in trafficgen sending `X`-byte packets. By default `pkt_size` is set to `60`.
`num_flows` | Setting `num_flows=N` will result in trafficgen sending `N` flows. By default `num_flows` is set to `10`.
`flow_duration` | Setting `flow_duration=X` will result in trafficgen generating flows that live for up to `X` seconds. By default `flow_duration` is set to `5` seconds.
`flow_rate` | Setting `flow_rate=R` will result in trafficgen generating `R` new flows per second. By default `flow_rate` is set to `num_flows` / `flow_duration`.
`arrival` | Setting `arrival` will change the distribution from which trafficgen generates flow IDs (5-tuples). It can be either `pareto` or `uniform`. By default `arrival` is set to `uniform`.
|`duration` | Setting `duration` will change the distribution from which trafficgen chooses flow lifetimes. It can be either `pareto` or `uniform`. By default `duration` is set to `uniform`.|

### HTTP Options

The following options are only applicable to ports sending in `http` mode.

Option | Description
------ | -----------
`num_flows` | Setting `num_flows=N` will result in trafficgen sending `N` flows. By default `num_flows` is set to `4000`.
`src_port` | Setting `src_port=X` will result in trafficgen generating HTTP traffic with TCP source ports starting with `X`. By default `src_port` is set to `1001`.
