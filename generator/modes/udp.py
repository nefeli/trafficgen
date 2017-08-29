import scapy.all as scapy
import socket
import struct

from generator.common import TrafficSpec, Pipeline, setup_mclasses


def atoh(ip):
    return struct.unpack("!L", socket.inet_aton(ip))[0]


def _build_pkt(spec, size):
    eth = scapy.Ether(src=spec.src_mac, dst=spec.dst_mac)
    ip = scapy.IP(src=spec.src_ip, dst=spec.dst_ip)
    udp = scapy.UDP(sport=10001, dport=10002, chksum=0)
    payload = ('hello' + '0123456789' * 200)[:size - len(eth / ip / udp)]
    pkt = eth / ip / udp / payload
    return str(pkt)


class UdpMode(object):
    name = 'udp'

    class Spec(TrafficSpec):

        def __init__(self, pkt_size=60, num_flows=1, imix=False, vlan=None,
                     rx_timestamp_offset=0, tx_timestamp_offset=0, **kwargs):
            self.pkt_size = pkt_size
            self.num_flows = num_flows
            self.imix = imix
            self.vlan = vlan
            if vlan:
                if not rx_timestamp_offset:
                    rx_timestamp_offset = 46
                if not tx_timestamp_offset:
                    tx_timestamp_offset = 46
            super(UdpMode.Spec,
                    self).__init__(rx_timestamp_offset=rx_timestamp_offset,
                                   tx_timestamp_offset=tx_timestamp_offset,
                                   **kwargs)

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

        # Setup tx pipeline
        pipeline = [
            Source(),
            Rewrite(templates=pkt_templates),
            RandomUpdate(fields=[{'offset': 30,
                                  'size': 4,
                                  'min': dst_ip,
                                  'max': dst_ip + num_flows - 1}]),
            IPChecksum()
        ]

        if spec.vlan:
            pipeline.append(VLANPush(tci=spec.vlan))

        return Pipeline(pipeline)

    @staticmethod
    def setup_rx_pipeline(cli, port, spec):
        setup_mclasses(cli, globals())
        return Pipeline([Sink()])
