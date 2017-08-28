import scapy.all as scapy
import socket
import struct

from generator.common import TrafficSpec, Pipeline, setup_mclasses

def atoh(ip):
      return struct.unpack("!L", socket.inet_aton(ip))[0]


def _build_pkt(spec, size, seqno=1):
    eth = scapy.Ether(src=spec.src_mac, dst=spec.dst_mac)
    ip = scapy.IP(src=spec.src_ip, dst=spec.dst_ip)
    udp = scapy.UDP(sport=0xDEAD, dport=0xBEEF, chksum=0)
    payload = chr(seqno)
    sz = size - len(eth/ip/udp)
    payload += 'x' * max((0, sz - len(payload)))
    pkt = eth
    if spec.vlan is not None:
        dot1q = scapy.Dot1Q(vlan=spec.vlan)
        pkt = pkt/dot1q
    pkt = pkt/ip/udp/payload
    return str(pkt)


class UdpMode(object):
    name = 'udp'

    class Spec(TrafficSpec):
        def __init__(self, pkt_size=60, num_flows=1, imix=False, vlan=None, ordered=False, **kwargs):
            self.pkt_size = pkt_size
            self.num_flows = num_flows
            self.imix = imix
            self.vlan = vlan
            self.ordered = ordered
            super(UdpMode.Spec, self).__init__(**kwargs)

        def __str__(self):
            s = super(UdpMode.Spec, self).__str__() + '\n'
            attrs = [
                ('pkt_size', lambda x: str(x)),
                ('num_flows', lambda x: str(x)),
                ('imix', lambda x: 'enabled' if x else 'disabled'),
                ('ordered', lambda x: 'enabled' if x else 'disabled')
            ]
            return s + self._attrs_to_str(attrs, 25)

        def __repr__(self):
            return self.__str__()

    @staticmethod
    def setup_tx_pipeline(cli, port, spec):
        setup_mclasses(cli, globals())
        if spec.imix:
            pkt_templates = [
                _build_pkt(spec, 60, 1),
                _build_pkt(spec, 60, 2),
                _build_pkt(spec, 60, 3),
                _build_pkt(spec, 60, 4),
                _build_pkt(spec, 60, 5),
                _build_pkt(spec, 60, 6),
                _build_pkt(spec, 60, 7),
                _build_pkt(spec, 590, 8),
                _build_pkt(spec, 590, 9),
                _build_pkt(spec, 590, 10),
                _build_pkt(spec, 1514, 11)
            ]
        else:
            if spec.ordered:
                pkt_templates = [_build_pkt(spec, spec.pkt_size, i + 1) for i in range(10)]
            else:
                pkt_templates = [_build_pkt(spec, spec.pkt_size)]

        num_flows = spec.num_flows
        dst_ip = atoh(spec.dst_ip)
        dst_ip_offset = 30
        if spec.vlan:
            dst_ip_offset += 4

        # Setup tx pipeline
        return Pipeline([
            Source(),
            Rewrite(templates=pkt_templates),
            RandomUpdate(fields=[{'offset': dst_ip_offset,
                                   'size': 4,
                                   'min': dst_ip,
                                   'max': dst_ip + num_flows - 1}]),
            IPChecksum()
        ])

    @staticmethod
    def setup_rx_pipeline(cli, port, spec):
        setup_mclasses(cli, globals())
        return Pipeline([Sink()])
