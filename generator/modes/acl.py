from pprint import pformat
import scapy.all as scapy

from generator.common import TrafficSpec, Pipeline, setup_mclasses

def _build_pkt(spec, size):
    eth = scapy.Ether(src=spec.src_mac, dst=spec.dst_mac)
    ip = scapy.IP(src=spec.src_ip, dst=spec.dst_ip)
    udp = scapy.UDP(sport=10001, dport=10002, chksum=0)
    payload = ('hello' + '0123456789' * 200)[:size-len(eth/ip/udp)]
    pkt = eth/ip/udp/payload
    return str(pkt)

class AclMode(object):
    name = 'acl'

    class Spec(TrafficSpec):
        def __init__(self, pkt_size=60, num_flows=1, imix=False, acls=list(),
                     **kwargs):
            self.pkt_size = pkt_size
            self.num_flows = num_flows
            self.imix = imix
            self.acls = acls
            super(AclMode.Spec, self).__init__(**kwargs)

        def __str__(self):
            s = super(UdpMode.Spec, self).__str__() + '\n'
            attrs = [
                ('pkt_size', lambda x: str(x)),
                ('num_flows', lambda x: str(x)),
                ('imix', lambda x: 'enabled' if x else 'disabled'),
                ('acls', lambda x: pformat(x))
            ]
            return s + self._attrs_to_str(attrs, 25)

        def __repr__(self):
            return self.__str__()

    @staticmethod
    def setup_tx_pipeline(cli, port, spec):
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

        # Setup tx pipeline
        return Pipeline([
            Source(),
            Rewrite(templates=pkt_templates),
            RandomUpdate(fields=[{'offset': 30,
                                   'size': 4,
                                   'min': 0x0a000001,
                                   'max': 0x0a000001 + num_flows - 1}]),
            IPChecksum()
        ])

    @staticmethod
    def setup_rx_pipeline(cli, port, spec):
        setup_mclasses(cli, globals())
        return Pipeline([ACL(rules=self.acls)])
