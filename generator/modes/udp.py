import scapy.all as scapy
import socket
import struct

from generator.common import TrafficSpec, Pipeline, RoundRobinProducers, setup_mclasses


def atoh(ip):
    return struct.unpack("!L", socket.inet_aton(ip))[0]


def _build_pkt(spec, size):
    eth = scapy.Ether(src=spec.src_mac, dst=spec.dst_mac)
    ip = scapy.IP(src=spec.src_ip, dst=spec.dst_ip)
    udp = scapy.UDP(sport=10001, dport=10002, chksum=0)
    payload = ('hello' + '0123456789' * 200)[:size - len(eth / ip / udp)]
    pkt = eth
    if spec.vlan is not None:
        dot1q = scapy.Dot1Q(vlan=spec.vlan)
        pkt = pkt / dot1q
    pkt = pkt / ip / udp / payload
    return str(pkt)


class UdpMode(object):
    name = 'udp'

    class Spec(TrafficSpec):

        def __init__(self, pkt_size=60, num_flows=1, imix=False, vlan=None, **kwargs):
            self.pkt_size = pkt_size
            self.num_flows = num_flows
            self.imix = imix
            self.vlan = vlan
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
        dst_ip = atoh(spec.dst_ip)
        dst_ip_offset = 30
        if spec.vlan:
            dst_ip_offset += 4

        # Setup tx pipeline
        src = Source()
        rewrite = Rewrite(templates=pkt_templates)
        rupdate = RandomUpdate(fields=[{'offset': dst_ip_offset,
                                        'size': 4,
                                        'min': dst_ip,
                                        'max': dst_ip + num_flows - 1}])
        cksum = IPChecksum()
        graph = {
            (src, 0): (rewrite, 0),
            (rewrite, 0): (rupdate, 0),
            (rupdate, 0): (cksum, 0),
        }
        periphery = {0: [(cksum, 0)]}
        return Pipeline(graph, periphery, RoundRobinProducers([src]))

    @staticmethod
    def setup_rx_pipeline(cli, port, spec):
        setup_mclasses(cli, globals())
        sink = Sink()
        graph = dict()
        periphery = {0: [(sink, 0)]}
        return Pipeline(graph, periphery)
