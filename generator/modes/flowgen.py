import scapy.all as scapy

from generator.common import TrafficSpec, Pipeline, setup_mclasses

class FlowGenMode(object):
    name = 'flowgen'

    class Spec(TrafficSpec):
        def __init__(self, pkt_size=60, num_flows=10, flow_duration=5,
                     flow_rate=None, arrival='uniform', duration='uniform',
                     src_port=1001, **kwargs):
            self.pkt_size = pkt_size
            self.num_flows = num_flows
            self.flow_duration = flow_duration
            self.flow_rate = flow_rate
            self.arrival = arrival
            self.duration = duration
            self.src_port = src_port
            super(FlowGenMode.Spec, self).__init__(**kwargs)

        def __str__(self):
            s = super(FlowGenMode.Spec, self).__str__() + '\n'
            attrs = [
                ('pkt_size', lambda x: str(x)),
                ('num_flows', lambda x: str(x)),
                ('flow_duration', lambda x: str(x) if x else 'auto'),
                ('arrival', lambda x: str(x)),
                ('duration', lambda x: str(x)),
                ('src_port', lambda x: str(x))
            ]
            return s + self._attrs_to_str(attrs, 25)

        def __repr__(self):
            return self.__str__()

    @staticmethod
    def setup_pipeline(cli, port, spec, qid):
        setup_mclasses(cli, globals())
        eth = scapy.Ether(src=spec.src_mac, dst=spec.dst_mac)
        ip = scapy.IP(src=spec.src_ip, dst=spec.dst_ip)
        tcp = scapy.TCP(sport=spec.src_port, dport=12345, seq=12345)
        payload = "meow"
        DEFAULT_TEMPLATE = str(eth/ip/tcp/payload)

        if spec.flow_rate is None:
            spec.flow_rate = spec.num_flows / spec.flow_duration

        num_cores = len(spec.cores)
        flows_per_core = spec.num_flows / num_cores

        if spec.pps is not None:
            pps_per_core = spec.pps / num_cores
        else:
            pps_per_core = 5e6

        # Setup tx pipeline
        tx_pipe = Pipeline([
            FlowGen(template=DEFAULT_TEMPLATE, pps=pps_per_core,
                    flow_rate=flows_per_core,
                    flow_duration=spec.flow_duration, arrival=spec.arrival,
                    duration=spec.duration, quick_rampup=True),
            IPChecksum()
        ])

        # Setup rx pipeline
        rx_pipe = Pipeline([Sink()])

        return (tx_pipe, rx_pipe)
