import etcd3
from functools import reduce
import json
from retrying import retry
import scapy.all as scapy
import socket
import struct

from generator.common import TrafficSpec, Pipeline, WeightedProducers, setup_mclasses


def ntoa(ip):
    return socket.inet_ntoa(struct.pack("!L", ip))


def atoh(ip):
    return struct.unpack("!L", socket.inet_aton(ip))[0]


def mac2int(mac):
    return reduce(lambda x, y: x | y, [z << 8 * j for j, z in
                                       enumerate(list(map(lambda x: int(x, 16), mac.split(':')))[::-1])])


def _build_pkt(spec, size):
    eth = scapy.Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')
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
                     vni=None, weight=1,
                     flow_duration=10, flow_rate=100, pps_per_flow=1000,
                     dst_macs=None,
                     tun_src_ip=None, tun_dst_ip=None,
                     min_src_ip=None, max_src_ip=None,
                     min_dst_ip=None, max_dst_ip=None,
                     min_src_port=None, max_src_port=None,
                     dummy_mac=None, outer_macs=None,
                     min_dst_port=None, max_dst_port=None,
                     proto=None, quick_rampup=False, etcd_host=None, **kwargs):
            self.pkt_size = pkt_size
            self.flow_rate = flow_rate
            self.vni = vni
            self.weight = weight
            self.flow_duration = flow_duration
            self.pps_per_flow = pps_per_flow
            if isinstance(dst_macs, str):
                self.dst_macs = dst_macs.split(' ')
            else:
                self.dst_macs = dst_macs
            self.tun_src_ip = tun_src_ip
            self.tun_dst_ip = tun_dst_ip
            self.min_src_ip = min_src_ip
            self.max_src_ip = max_src_ip
            self.min_dst_ip = min_dst_ip
            self.max_dst_ip = max_dst_ip
            self.dummy_mac = dummy_mac
            self.min_src_port = min_src_port
            self.max_src_port = max_src_port
            self.min_dst_port = min_dst_port
            self.max_dst_port = max_dst_port
            self.proto = proto
            self.quick_rampup = quick_rampup
            self.etcd_host = etcd_host
            self.outer_macs = outer_macs

    class Spec(TrafficSpec):

        def __init__(self, etcd_host=None, tenants=None, core=None,
                     rx_timestamp_offset=0, tx_timestamp_offset=0, **kwargs):
            self.core = core
            self.tenants = list()
            for tenant in tenants:
                tenant['etcd_host'] = etcd_host
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

    def get_vni_macs(vni, etcd_host):
        @retry
        def get_etcd_handle(etcd_host):
            host, port = etcd_host.split(':')
            client = etcd3.client(host=host, port=port)
            return client

        def get_or_watch(client, key):
            ret = client.get(key)
            if ret:
                return ret[0]
            return client.watch_once(key).value

        client = get_etcd_handle(etcd_host)
        dsts_key = '/pangolin/v1/vxlan/instantiate/vnis/{}'.format(vni)
        dsts = json.loads(get_or_watch(client, dsts_key))
        return [dst['mac'] for dst in dsts['destinations']]

    def setup_tenant_tx(cli, core, src_mac, spec, pipeline):
        if not spec.outer_macs:
            spec.outer_macs = TestingMode.get_vni_macs(spec.vni, spec.etcd_host)

        setup_mclasses(cli, globals())

        pkt_template = _build_pkt(spec, spec.pkt_size)
        args = TestingMode.make_args(spec)

        vencap = VXLANEncap()
        ipencap = IPEncap()
        ethencap = EtherEncap()
        pipeline.add_edge(vencap, 0, ipencap, 0)
        pipeline.add_edge(ipencap, 0, ethencap, 0)

        # meh.
        if len(spec.dst_macs) == 0:
            spec.dst_macs = [spec.dst_mac]

        src_mac64 = mac2int(src_mac)
        dst_mac64 = mac2int(spec.dst_macs[0])

        # Setup forward traffic
        src = FlowGen(
            name='flowgen_c{}_p{}'.format(core, spec.vni), **args)
        cksum = IPChecksum()
        setmd = SetMetadata(
            attrs=[
                {'name': 'tun_ip_src', 'size': 4,
                    'value_int': atoh(spec.tun_src_ip)},
                                    {'name': 'tun_ip_dst', 'size': 4, 'value_int': atoh(
                                        spec.tun_dst_ip)},
                                    {'name': 'tun_id', 'size': 4,
                                        'value_int': spec.vni},
                                    {'name': 'ether_src', 'size':
                                        6, 'value_int': src_mac64},
                                    {'name': 'ether_dst', 'size': 6, 'value_int': dst_mac64}])
        pipeline.add_edge(src, 0, cksum, 0)
        pipeline.add_edge(cksum, 0, setmd, 0)

        # MAC load balancing
        mac_lb = HashLB(mode='l4')
        mac_lb.set_gates(gates=list(range(len(spec.dst_macs))))

        for i, mac in enumerate(spec.dst_macs):
            mac64 = mac2int(mac)
            update = Update(fields=[{'offset': 0, 'size': 6, 'value': mac64}])
            pipeline.add_edge(mac_lb, i, update, 0)
            pipeline.add_edge(update, 0, vencap, 0)

        pipeline.add_edge(setmd, 0, mac_lb, 0)

        outer_mac_lb = HashLB(mode='l4')
        outer_mac_lb.set_gates(gates=list(range(len(spec.outer_macs))))
        pipeline.add_edge(ethencap, 0, outer_mac_lb, 0)
        for i, mac in enumerate(spec.outer_macs):
            mac64 = mac2int(mac)
            update = Update(fields=[{'offset': 0, 'size': 6, 'value': mac64}])
            pipeline.add_edge(outer_mac_lb, i, update, 0)
            pipeline.add_peripheral_edge(0, update, 0)

        return src

    @staticmethod
    def setup_tx_pipeline(cli, port, spec, pipeline):
        setup_mclasses(cli, globals())

        producers = dict()
        for tenant in spec.tenants:
            prod = TestingMode.setup_tenant_tx(cli, spec.core, spec.src_mac, tenant, pipeline)
            producers[prod] = tenant.weight

        pipeline.set_producers(WeightedProducers(producers))

    def setup_tenant_rx(cli, core, src_mac, spec, pipeline, port_out):
        if not spec.outer_macs:
            spec.outer_macs = TestingMode.get_vni_macs(spec.vni, spec.etcd_host)

        setup_mclasses(cli, globals())

        arp_blast = ArpBlast(sha=spec.dummy_mac)
        vxencap = VXLANEncap()
        ipencap = IPEncap()
        ethencap = EtherEncap()

        src_mac64 = mac2int(src_mac)
        dst_mac64 = mac2int(spec.outer_macs[0])

        setmd = SetMetadata(
            attrs=[
                {'name': 'tun_ip_src', 'size': 4,
                    'value_int': atoh(spec.tun_src_ip)},
                                    {'name': 'tun_ip_dst', 'size': 4, 'value_int': atoh(
                                        spec.tun_dst_ip)},
                                    {'name': 'tun_id', 'size': 4,
                                        'value_int': spec.vni},
                                    {'name': 'ether_src', 'size':
                                        6, 'value_int': src_mac64}])
        pipeline.add_edge(setmd, 0, vxencap, 0)

        pipeline.add_edge(arp_blast, 0, setmd, 0)
        pipeline.add_edge(vxencap, 0, ipencap, 0)
        pipeline.add_edge(ipencap, 0, ethencap, 0)
        pipeline.add_edge(ethencap, 0, port_out, 0)

        return arp_blast

    @staticmethod
    def setup_rx_pipeline(cli, port, spec, pipeline, port_out):
        setup_mclasses(cli, globals())

        vpop = VLANPop()
        get_sender = SetMetadata(attrs=[{'name': 'ether_dst', 'size': 6, 'offset': 6}])
        vxdecap = VXLANDecap()
        pipeline.add_edge(vpop, 0, get_sender, 0)
        pipeline.add_edge(get_sender, 0, vxdecap, 0)
        pipeline.add_peripheral_edge(0, vpop, 0)

        sink = Sink()
        em = ExactMatch(fields=[{'attr_name':'tun_id', 'num_bytes':4}])
        em.set_default_gate(gate=0)
        pipeline.add_edge(em, 0, sink, 0)
        pipeline.add_edge(vxdecap, 0, em, 0)


        # XXX: the calls to htonl() below shouldn't be necessary. fix VXLANDecap
        # or ExactMatch
        gate = 1
        for tenant in spec.tenants:
            arp = TestingMode.setup_tenant_rx(cli, spec.core, spec.src_mac, tenant, pipeline, port_out)
            em.add(fields=[{'value_int': socket.htonl(tenant.vni)}],
                   gate=gate + 1)
            pipeline.add_edge(em, gate + 1, arp, 0)
            gate += 1

    @staticmethod
    def make_args(spec):
        pkt_template = _build_pkt(spec, spec.pkt_size)
        pps = spec.flow_rate * spec.pps_per_flow * spec.flow_duration
        src_ip_range = atoh(spec.max_src_ip) - atoh(spec.min_src_ip)
        dst_ip_range = atoh(spec.max_dst_ip) - atoh(spec.min_dst_ip)
        src_port_range = spec.max_src_port - spec.min_src_port
        dst_port_range = spec.max_dst_port - spec.min_dst_port
        return {'template': pkt_template,
                'pps': pps,
                'flow_rate': spec.flow_rate,
                'flow_duration': spec.flow_duration,
                'arrival': 'uniform',
                'duration': 'uniform',
                'quick_rampup': spec.quick_rampup,
                'ip_src_range': src_ip_range,
                'ip_dst_range': dst_ip_range,
                'port_src_range': src_port_range,
                'port_dst_range': dst_port_range}
