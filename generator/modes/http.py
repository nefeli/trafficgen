import scapy.all as scapy

from generator.common import TrafficSpec, Pipeline
from generator.modes import setup_mclasses

class HttpMode(object):
    name = 'http'

    class Spec(TrafficSpec):
        def __init__(self, num_flows=4000, src_port=1001, **kwargs):
            self.num_flows = num_flows
            self.src_port = src_port
            super(HttpMode.Spec, self).__init__(**kwargs)

        def __str__(self):
            s = super(HttpMode.Spec, self).__str__() + '\n'
            attrs = [
                ('num_flows', lambda x: str(x)),
                ('src_port', lambda x: str(x)),
            ]
            return s + self._attrs_to_str(attrs, 25)

        def __repr__(self):
            return self.__str__()

    @staticmethod
    def setup_pipeline(cli, port, spec, qid):
        setup_mclasses(cli, globals())
        SEQNO = 12345
        PORT_HTTP = 80
        eth = scapy.Ether(src=spec.src_mac, dst=spec.dst_mac)
        ip = scapy.IP(src=spec.src_ip, dst=spec.dst_ip)
        tcp = scapy.TCP(sport=spec.src_port, dport=PORT_HTTP, seq=SEQNO)

        payload_prefix = 'GET /pub/WWW/TheProject.html HTTP/1.1\r\nHost: www.'
        payload = payload_prefix + 'aaa.com\r\n\r\n'
        pkt_headers = eth/ip/tcp
        pkt_template = str(eth/ip/tcp/payload)

        num_cores = len(spec.cores)
        flows_per_core = spec.num_flows / num_cores
        if spec.pps is not None:
            pps_per_core = spec.pps / num_cores
        else:
            pps_per_core = 5e6

        # Setup tx pipeline
        tx_pipe = Pipeline([
            FlowGen(template=pkt_template, pps=pps_per_core,
                    flow_rate=flows_per_core, flow_duration=5,
                    arrival='uniform', duration='uniform',
                    quick_rampup=False),
            RandomUpdate(fields=[{'offset': len(pkt_headers)  + len(payload_prefix),
                         'size': 1, 'min': 97, 'max': 122}]),
            RandomUpdate(fields=[{'offset': len(pkt_headers)  + \
                                            len(payload_prefix) + 1,
                                  'size': 1, 'min': 97, 'max': 122}]),
            IPChecksum(),
            Timestamp(),
            QueueOut(port=port, qid=qid)
        ])

        # Setup rx pipeline
        rx_pipe = Pipeline([QueueInc(port=port, qid=qid), Measure(), Sink()])

        return (tx_pipe, rx_pipe)
