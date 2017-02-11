import scapy.all as scapy

from generator.common import TrafficSpec, Pipeline
from generator.modes import setup_mclasses, create_rate_limit_tree

def _build_pkt(spec, size):
    eth = scapy.Ether(src=spec.src_mac, dst=spec.dst_mac)
    ip = scapy.IP(src=spec.src_ip, dst=spec.dst_ip)
    udp = scapy.UDP(sport=10001, dport=10002, chksum=0)
    payload = ('hello' + '0123456789' * 200)[:size-len(eth/ip/udp)]
    pkt = eth/ip/udp/payload
    return str(pkt)

class UdpMode(object):
    name = 'udp'

    class Spec(TrafficSpec):
        def __init__(self, pkt_size=60, num_flows=1, imix=False, **kwargs):
            self.pkt_size = pkt_size
            self.num_flows = num_flows
            self.imix = imix
            super(UdpMode.Spec, self).__init__(**kwargs)

    def __str__(self):
        s = super(UdpMode.Spec, self).__str__() + '\n'
        attrs = [
            ('pkt_size', lambda x: str(x)),
            ('num_flows', lambda x: str(x)),
            ('imix', lambda x: 'enabled' if x else 'disabled')
        ]
        return s + self._attrs_to_str(attrs, 25)

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def setup_pipeline(cli, port, spec):
        setup_mclasses(cli, globals())
        if spec.imix:
            pkt_templates = [
                _build_pkt(spec, 60),
                _build_pkt(spec, 60),
                _build_pkt(spec, 60),
                _build_pkt(spec, 60),
                _build_pkt(spec, 60),
                _build_pkt(spec, 60),
                _build_pkt(spec, 60),
                _build_pkt(spec, 590),
                _build_pkt(spec, 590),
                _build_pkt(spec, 590),
                _build_pkt(spec, 1514)
            ]
        else:
            pkt_templates = [_build_pkt(spec, spec.pkt_size)]

        num_flows = spec.num_flows

        tx_pipes = dict()
        rx_pipes = dict()

        cli.bess.pause_all()

        num_cores = len(spec.cores)
        if spec.mbps is not None:
            bps_per_core = long(1e6 * spec.mbps / num_cores)
        elif spec.pps is not None:
            pps_per_core = long(spec.pps / num_cores)

        for i, core in enumerate(spec.cores):
            cli.bess.add_worker(wid=core, core=core)
            src = Source()
            if spec.mbps is not None:
                rr_name, rl_name, leaf_name = create_rate_limit_tree(cli,
                                                                      core,
                                                                      'bit',
                                                                      bps_per_core)
                cli.bess.attach_task(src.name, tc=leaf_name)
            elif spec.pps is not None:
                rr_name, rl_name, leaf_name = create_rate_limit_tree(cli,
                                                                      core,
                                                                      'packet',
                                                                      pps_per_core)
                cli.bess.attach_task(src.name, tc=leaf_name)
            else:
                rr_name = None
                rl_name = None
                leaf_name = None
                cli.bess.attach_task(src.name, 0, wid=core)

            # Setup tx pipeline
            tx_pipe = [
                src,
                Rewrite(templates=pkt_templates),
                RandomUpdate(fields=[{'offset': 30,
                                       'size': 4,
                                       'min': 0x0a000001,
                                       'max': 0x0a000001 + num_flows - 1}]),
                IPChecksum(),
                Timestamp(),
                QueueOut(port=port, qid=i)
            ]
            tx_pipes[core] = Pipeline(tx_pipe, rl_name)

            # Setup rx pipeline
            rx_pipe = [QueueInc(port=port, qid=i), Measure(), Sink()]
            cli.bess.attach_task(rx_pipe[0].name, 0, wid=core)
            rx_pipes[core] = Pipeline(rx_pipe)

        cli.bess.resume_all()

        return (tx_pipes, rx_pipes)
