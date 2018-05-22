from functools import reduce
import scapy.all as scapy
import socket
import struct

from generator.common import TrafficSpec, Pipeline, RoundRobinProducers, WeightedProducers, setup_mclasses


def ntoa(ip):
    return socket.inet_ntoa(struct.pack("!L", ip))


def atoh(ip):
    return struct.unpack("!L", socket.inet_aton(ip))[0]


def mac2int(mac):
    return reduce(lambda x, y: x | y, [z << 8 * j for j, z in
                                       enumerate(list(map(lambda x: int(x, 16), mac.split(':')))[::-1])])


def _build_pkt(spec, size, reverse=False):
    eth = scapy.Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')
    if reverse:
        ip = scapy.IP(src=spec.min_dst_ip, dst=spec.min_src_ip)
        udp = scapy.UDP(sport=spec.min_dst_port, dport=spec.min_src_port)
    else:
        ip = scapy.IP(src=spec.min_src_ip, dst=spec.min_dst_ip)
        udp = scapy.UDP(sport=spec.min_src_port, dport=spec.min_dst_port)
    sz = size - len(eth / ip / udp)
    payload = ('hello' + '0123456789' * 200)[:sz]
    pkt = eth / ip / udp / payload
    return bytes(pkt)


class TestingMode(object):
    name = 'testing'

    class Tenant(object):
        def __init__(self, pkt_size=60,
                     fwd_pid=None, rev_pid=None, fwd_weight=1, rev_weight=1,
                     flow_duration=10, flow_rate=100, pps_per_flow=1000,
                     fwd_dst_macs=None, rev_dst_macs=None,
                     tun_src_ip=None, tun_dst_ip=None,
                     min_src_ip=None, max_src_ip=None,
                     min_dst_ip=None, max_dst_ip=None,
                     min_src_port=None, max_src_port=None,
                     dummy_mac=None, outer_macs=None,
                     min_dst_port=None, max_dst_port=None,
                     proto=None, quick_rampup=False, **kwargs):
            self.pkt_size = pkt_size
            self.flow_rate = flow_rate
            self.fwd_pid = fwd_pid
            self.rev_pid = rev_pid
            self.fwd_weight = fwd_weight
            self.rev_weight = rev_weight
            self.flow_duration = flow_duration
            self.pps_per_flow = pps_per_flow
            if isinstance(fwd_dst_macs, str):
                self.fwd_dst_macs = fwd_dst_macs.split(' ')
            else:
                self.fwd_dst_macs = fwd_dst_macs
            if isinstance(rev_dst_macs, str):
                self.rev_dst_macs = rev_dst_macs.split(' ')
            else:
                self.rev_dst_macs = rev_dst_macs
            self.tun_src_ip = tun_src_ip
            self.tun_dst_ip = tun_dst_ip
            self.min_src_ip = min_src_ip
            self.max_src_ip = max_src_ip
            self.min_dst_ip = min_dst_ip
            self.max_dst_ip = max_dst_ip
            self.dummy_mac = dummy_mac
            if isinstance(outer_macs, str):
                self.outer_macs = outer_macs.split(' ')
            else:
                self.outer_macs = outer_macs
            self.min_src_port = min_src_port
            self.max_src_port = max_src_port
            self.min_dst_port = min_dst_port
            self.max_dst_port = max_dst_port
            self.proto = proto
            self.quick_rampup = quick_rampup

    class Spec(TrafficSpec):

        def __init__(self, tenants=None, core=None, 
                     rx_timestamp_offset=0, tx_timestamp_offset=0, **kwargs):
            self.core = core
            self.tenants = list()
            for tenant in tenants:
                self.tenants.append(TestingMode.Tenant(**tenant))

            if not rx_timestamp_offset:
                rx_timestamp_offset = 106
            if not tx_timestamp_offset:
                tx_timestamp_offset = 106

            super(TestingMode.Spec, self).__init__(
                    rx_timestamp_offset=rx_timestamp_offset,
                    tx_timestamp_offset=tx_timestamp_offset,
                    **kwargs)

        def __str__(self):
            return super(TestingMode.Spec, self).__str__() + '\n'

        def __repr__(self):
            return self.__str__()

    def setup_tenant_tx(cli, core, src_mac, spec, pipeline):
        setup_mclasses(cli, globals())

        fwd_pkt_template = _build_pkt(spec, spec.pkt_size)
        rev_pkt_template = _build_pkt(spec, spec.pkt_size, True)
        args = TestingMode.make_args(spec)

        vencap = VXLANEncap()
        ipencap = IPEncap()
        ethencap = EtherEncap()
        pipeline.add_edge(vencap, 0, ipencap, 0)
        pipeline.add_edge(ipencap, 0, ethencap, 0)

        # meh.
        if len(spec.fwd_dst_macs) == 0:
            spec.fwd_dst_macs = [spec.fwd_dst_mac]
        if len(spec.rev_dst_macs) == 0:
            spec.rev_dst_macs = [spec.rev_dst_mac]

        src_mac64 = mac2int(src_mac)
        fwd_dst_mac64 = mac2int(spec.fwd_dst_macs[0])
        rev_dst_mac64 = mac2int(spec.rev_dst_macs[0])

        # Setup forward traffic
        src_fwd = FlowGen(
            name='flowgen_fwd_c{}_p{}'.format(core, spec.fwd_pid), **args['fwd'])
        cksum_fwd = IPChecksum()
        setmd_fwd = SetMetadata(
            attrs=[
                {'name': 'tun_ip_src', 'size': 4,
                    'value_int': atoh(spec.tun_src_ip)},
                                    {'name': 'tun_ip_dst', 'size': 4, 'value_int': atoh(
                                        spec.tun_dst_ip)},
                                    {'name': 'tun_id', 'size': 4,
                                        'value_int': spec.fwd_pid},
                                    {'name': 'ether_src', 'size':
                                        6, 'value_int': src_mac64},
                                    {'name': 'ether_dst', 'size': 6, 'value_int': fwd_dst_mac64}])
        pipeline.add_edge(src_fwd, 0, cksum_fwd, 0)
        pipeline.add_edge(cksum_fwd, 0, setmd_fwd, 0)

        # Setup reverse traffic
        src_rev = FlowGen(
            name='flowgen_rev_c{}_p{}'.format(core, spec.rev_pid), **args['rev'])
        cksum_rev = IPChecksum()
        setmd_rev = SetMetadata(
            attrs=[
                {'name': 'tun_ip_src', 'size': 4,
                    'value_int': atoh(spec.tun_src_ip)},
                                    {'name': 'tun_ip_dst', 'size': 4, 'value_int': atoh(
                                        spec.tun_dst_ip)},
                                    {'name': 'tun_id', 'size': 4,
                                        'value_int': spec.rev_pid},
                                    {'name': 'ether_src', 'size':
                                        6, 'value_int': src_mac64},
                                    {'name': 'ether_dst', 'size': 6, 'value_int': rev_dst_mac64}])
        pipeline.add_edge(src_rev, 0, cksum_rev, 0)
        pipeline.add_edge(cksum_rev, 0, setmd_rev, 0)

        # MAC load balancing
        fwd_mac_lb = HashLB(mode='l4')
        fwd_mac_lb.set_gates(gates=list(range(len(spec.fwd_dst_macs))))

        rev_mac_lb = HashLB(mode='l4')
        rev_mac_lb.set_gates(gates=list(range(len(spec.rev_dst_macs))))

        for i, mac in enumerate(spec.fwd_dst_macs):
            mac64 = mac2int(mac)
            update = Update(fields=[{'offset': 0, 'size': 6, 'value': mac64}])
            pipeline.add_edge(fwd_mac_lb, i, update, 0)
            pipeline.add_edge(update, 0, vencap, 0)

        for i, mac in enumerate(spec.rev_dst_macs):
            mac64 = mac2int(mac)
            update = Update(fields=[{'offset': 0, 'size': 6, 'value': mac64}])
            pipeline.add_edge(rev_mac_lb, i, update, 0)
            pipeline.add_edge(update, 0, vencap, 0)

        pipeline.add_edge(setmd_fwd, 0, fwd_mac_lb, 0)
        pipeline.add_edge(setmd_rev, 0, rev_mac_lb, 0)

        outer_mac_lb = HashLB(mode='l4')
        outer_mac_lb.set_gates(gates=list(range(len(spec.outer_macs))))
        pipeline.add_edge(ethencap, 0, outer_mac_lb, 0)
        for i, mac in enumerate(spec.outer_macs):
            mac64 = mac2int(mac)
            update = Update(fields=[{'offset': 0, 'size': 6, 'value': mac64}])
            pipeline.add_edge(outer_mac_lb, i, update, 0)
            pipeline.add_peripheral_edge(0, update, 0)

        return src_fwd, src_rev

    @staticmethod
    def setup_tx_pipeline(cli, port, spec, pipeline):
        setup_mclasses(cli, globals())

        producers = list()
        for tenant in spec.tenants:
            fwd_prod, rev_prod = TestingMode.setup_tenant_tx(cli, spec.core, spec.src_mac, tenant, pipeline)
            producers.extend([fwd_prod, rev_prod])

        pipeline.set_producers(RoundRobinProducers(producers))

    def setup_tenant_rx(cli, core, src_mac, spec, pipeline, port_out):
        setup_mclasses(cli, globals())

        fwd_arp_blast = ArpBlast(sha=spec.dummy_mac)
        rev_arp_blast = ArpBlast(sha=spec.dummy_mac)
        vpop = VLANPop()
        vxdecap = VXLANDecap()
        vxencap = VXLANEncap()
        ipencap = IPEncap()
        ethencap = EtherEncap()

        src_mac64 = mac2int(src_mac)
        fwd_dst_mac64 = mac2int(spec.fwd_dst_macs[0])
        rev_dst_mac64 = mac2int(spec.rev_dst_macs[0])

        setmd_fwd = SetMetadata(
            attrs=[
                {'name': 'tun_ip_src', 'size': 4,
                    'value_int': atoh(spec.tun_src_ip)},
                                    {'name': 'tun_ip_dst', 'size': 4, 'value_int': atoh(
                                        spec.tun_dst_ip)},
                                    {'name': 'tun_id', 'size': 4,
                                        'value_int': spec.fwd_pid},
                                    {'name': 'ether_src', 'size':
                                        6, 'value_int': src_mac64},
                                    {'name': 'ether_dst', 'size': 6, 'value_int': fwd_dst_mac64}])
        setmd_rev = SetMetadata(
            attrs=[
                {'name': 'tun_ip_src', 'size': 4,
                    'value_int': atoh(spec.tun_src_ip)},
                                    {'name': 'tun_ip_dst', 'size': 4, 'value_int': atoh(
                                        spec.tun_dst_ip)},
                                    {'name': 'tun_id', 'size': 4,
                                        'value_int': spec.rev_pid},
                                    {'name': 'ether_src', 'size':
                                        6, 'value_int': src_mac64},
                                    {'name': 'ether_dst', 'size': 6, 'value_int': rev_dst_mac64}])

        em = ExactMatch(fields=[{'attr_name':'tun_id', 'num_bytes':4}])
        em.set_default_gate(gate=0)
        # XXX: this call to htonl() shouldn't be necessary. fix VXLANDecap or ExactMatch
        em.add(fields=[{'value_int': socket.htonl(spec.fwd_pid)}], gate=1)
        em.add(fields=[{'value_int': socket.htonl(spec.rev_pid)}], gate=2)

        pipeline.add_edge(setmd_fwd, 0, vxencap, 0)
        pipeline.add_edge(setmd_rev, 0, vxencap, 0)

        pipeline.add_edge(vpop, 0, vxdecap, 0)

        sink = Sink()

        pipeline.add_edge(vxdecap, 0, em, 0)
        pipeline.add_edge(em, 0, sink, 0)
        pipeline.add_edge(em, 1, fwd_arp_blast, 0)
        pipeline.add_edge(em, 2, rev_arp_blast, 0)

        pipeline.add_edge(fwd_arp_blast, 0, setmd_fwd, 0)
        pipeline.add_edge(rev_arp_blast, 0, setmd_rev, 0)
        pipeline.add_edge(vxencap, 0, ipencap, 0)
        pipeline.add_edge(ipencap, 0, ethencap, 0)
        pipeline.add_edge(ethencap, 0, port_out, 0)

        pipeline.add_peripheral_edge(0, vpop, 0)

    @staticmethod
    def setup_rx_pipeline(cli, port, spec, pipeline, port_out):
        setup_mclasses(cli, globals())

        for tenant in spec.tenants:
            TestingMode.setup_tenant_rx(cli, spec.core, spec.src_mac, tenant, pipeline, port_out)

    @staticmethod
    def make_args(spec):
        fwd_pkt_template = _build_pkt(spec, spec.pkt_size)
        rev_pkt_template = _build_pkt(spec, spec.pkt_size, True)
        pps = spec.flow_rate * spec.pps_per_flow * spec.flow_duration
        src_ip_range = atoh(spec.max_src_ip) - atoh(spec.min_src_ip)
        dst_ip_range = atoh(spec.max_dst_ip) - atoh(spec.min_dst_ip)
        src_port_range = spec.max_src_port - spec.min_src_port
        dst_port_range = spec.max_dst_port - spec.min_dst_port
        return {'fwd': {'template': fwd_pkt_template,
                        'pps': pps / 2,
                        'flow_rate': spec.flow_rate / 2,
                        'flow_duration': spec.flow_duration,
                        'arrival': 'uniform',
                        'duration': 'uniform',
                        'quick_rampup': spec.quick_rampup,
                        'ip_src_range': src_ip_range,
                        'ip_dst_range': dst_ip_range,
                        'port_src_range': src_port_range,
                        'port_dst_range': dst_port_range},
                'rev': {'template': rev_pkt_template,
                        'pps': pps / 2,
                        'flow_rate': spec.flow_rate / 2,
                        'flow_duration': spec.flow_duration,
                        'arrival': 'uniform',
                        'duration': 'uniform',
                        'quick_rampup': spec.quick_rampup,
                        'ip_src_range': dst_ip_range,
                        'ip_dst_range': src_ip_range,
                        'port_src_range': dst_port_range,
                        'port_dst_range': src_port_range}}
