import scapy.all as scapy

from generator.common import TrafficSpec, Pipeline, setup_mclasses

def _build_pkt(spec, size):
    eth = scapy.Ether(src=spec.src_mac, dst=spec.dst_mac)
    ip = scapy.IP(src=spec.src_ip, dst=spec.dst_ip)
    udp = scapy.UDP(sport=10001, dport=10002, chksum=0)
    pkt = eth/ip/udp
    payload = ('hello' + '0123456789' * 200)[:size-len(pkt)]
    return str(pkt/payload)

class Dot1QMode(object):
    name = 'dot1q'

    class Spec(TrafficSpec):
        def __init__(self, pkt_size=60, tci_min=0, tci_max=0xFFFF, imix=False, **kwargs):
            super(Dot1QMode.Spec, self).__init__(**kwargs)
            self.pkt_size = pkt_size
            self.imix = imix
            self.rx_timestamp_offset = 46
            self.tx_timestamp_offset = 46
            self.tci_min = tci_min
            self.tci_max = tci_max

        def __str__(self):
            s = super(Dot1QMode.Spec, self).__str__() + '\n'
            attrs = [
                ('pkt_size', lambda x: str(x)),
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

        # Setup tx pipeline
        return Pipeline([
            Source(),
            Rewrite(templates=pkt_templates),
            IPChecksum(),
            VLANPush(),
            RandomUpdate(fields=[{'offset': 18,
                                   'size': 2,
                                   'min': spec.tci_min,
                                   'max': spec.tci_max}]),
        ])

    @staticmethod
    def setup_rx_pipeline(cli, port, spec):
        setup_mclasses(cli, globals())
        return Pipeline([Sink()])
