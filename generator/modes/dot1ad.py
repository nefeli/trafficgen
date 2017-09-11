import scapy.all as scapy

from generator.common import TrafficSpec, Pipeline, RoundRobinProducers, setup_mclasses


def _build_pkt(spec, size):
    eth = scapy.Ether(src=spec.src_mac, dst=spec.dst_mac)
    ip = scapy.IP(src=spec.src_ip, dst=spec.dst_ip)
    udp = scapy.UDP(sport=10001, dport=10002, chksum=0)
    pkt = eth / ip / udp
    payload = ('hello' + '0123456789' * 200)[:size - len(pkt)]
    return str(pkt / payload)


class Dot1ADMode(object):
    name = 'dot1ad'

    class Spec(TrafficSpec):

        def __init__(self, pkt_size=60, tci1_min=0, tci1_max=0xFFFF,
                     tci2_min=0, tci2_max=0xFFFF, imix=False, **kwargs):
            super(Dot1ADMode.Spec, self).__init__(**kwargs)
            self.pkt_size = pkt_size
            self.imix = imix
            self.rx_timestamp_offset = 50
            self.tx_timestamp_offset = 50
            self.tci1_min = tci1_min
            self.tci1_max = tci1_max
            self.tci2_min = tci2_min
            self.tci2_max = tci2_max

        def __str__(self):
            s = super(Dot1ADMode.Spec, self).__str__() + '\n'
            attrs = [
                ('pkt_size', lambda x: str(x)),
                ('imix', lambda x: 'enabled' if x else 'disabled'),
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
        src = Source()
        rewrite = Rewrite(templates=pkt_templates)
        cksum = IPChecksum()
        vpush1 = VLANPush()
        vpush2 = VLANPush()
        rupdate1 = RandomUpdate(fields=[{'offset': 14,
                                         'size': 2,
                                         'min': spec.tci1_min,
                                         'max': spec.tci1_max}])
        rupdate2 = RandomUpdate(fields=[{'offset': 18,
                                         'size': 2,
                                         'min': spec.tci2_min,
                                         'max': spec.tci2_max}])
        graph = {
            (src, 0): (rewrite, 0),
            (rewrite, 0): (cksum, 0),
            (cksum, 0): (vpush1, 0),
            (vpush1, 0): (vpush2, 0),
            (vpush2, 0): (rupdate1, 0),
            (rupdate1, 0): (rupdate2, 0),
        }
        periphery = {0: [(rupdate2, 0)]}
        return Pipeline(graph, periphery, RoundRobinProducers([src]))

    @staticmethod
    def setup_rx_pipeline(cli, port, spec):
        setup_mclasses(cli, globals())
        sink = Sink()
        graph = dict()
        periphery = {0: [(sink, 0)]}
        return Pipeline(graph, periphery)
