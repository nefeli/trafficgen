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

## Options 

There are several knobs you can tweak to control traffic. They are specified
like `foo="bar", baz=3`.

### General Options

The following options are applicable to all modes of traffic.

Option | Description
------ | -----------
`loss_rate` | Setting `loss_rate=X` will result in trafficgen sending traffic at rate such that it sees a frame last rate of `X` (in `[0,1]`) as defined by RFC2544. If `loss_rate` is set, `pps` must be set to the initial sending rate. By befault `loss_rate` is not set and trafficgen sends at whatever rate you tell it to.
`latency` | Setting `latency=1` will result in trafficgen sending traffic at a low rate (100mbps by default) to make measurements of the mean, median and 99th percentile round-trip latencies. Latency measurements are reported in the output of `monitor port` as `rtt_avg`, `rtt_med` and `rtt_99`. By default `latency` is not set.
`pps` | Setting `pps=X` will result in trafficgen sending traffic at `X` packets per second. When set with `loss_rate`, trafficgen will start sending at `X` packets per second before adjusting the sending rate. By default `pps` is not set, meaning trafficgen will try to send at line rate.
`mbps` | Setting `mbps=X` will result in trafficgen sending traffic at `X` megabits per second. By default `mbps` is not set and trafficgen will try to send at line rate.
`cores` | Setting `cores` will split the work of generating traffic on a port across multiple cores. For example, setting `cores="0 1 2"` will result in trafficgen splitting traffic across cores `0`, `1` and `2`. By default `cores` is set to `"0"`.
`src_mac`, `dst_mac` | Setting `src_mac=X` and `dst_mac=Y` will result in trafficgen setting the source and destination Ethernet addresses to `X` and `Y` respectively. By default `src_mac` is set to the Ethernet address of the sending port and `dst_port` is set to `02:1e:67:9f:4d:bb`.
`src_ip`, `dst_ip` | Setting `src_ip=X` and `dst_ip=Y` will result in trafficgen generating flows with source and destination IP addresses starting at `X` and `Y` respectively. By default `src_ip` and `dst_ip` are `192.168.0.1` and `10.0.0.1` respectively.

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
