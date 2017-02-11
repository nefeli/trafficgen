import scapy.all as scapy

from generator.common import TrafficSpec, Pipeline
from generator.modes import setup_mclasses, create_rate_limit_tree

class FlowGenMode(object):
    name = 'flowgen'

    class Spec(TrafficSpec):
        def __init__(self, pkt_size=60, num_flows=10, flow_duration=5,
                     flow_rate=None, arrival='uniform', duration='uniform',
                     src_port=1001, **kwargs):
            self.pkt_size = pkt_size
            self.num_flows = num_flows
            self.flow_duration = flow_duration
            self.flow_rate = flow_rate
            self.arrival = arrival
            self.duration = duration
            self.src_port = src_port
            super(FlowGenMode.Spec, self).__init__(**kwargs)

        def __str__(self):
            s = super(FlowGenMode.Spec, self).__str__() + '\n'
            attrs = [
                ('pkt_size', lambda x: str(x)),
                ('num_flows', lambda x: str(x)),
                ('flow_duration', lambda x: str(x) if x else 'auto'),
                ('arrival', lambda x: str(x)),
                ('duration', lambda x: str(x)),
                ('src_port', lambda x: str(x))
            ]
            return s + self._attrs_to_str(attrs, 25)

        def __repr__(self):
            return self.__str__()

    @staticmethod
    def setup_pipeline(cli, port, spec):
        setup_mclasses(cli, globals())
        eth = scapy.Ether(src=spec.src_mac, dst=spec.dst_mac)
        ip = scapy.IP(src=spec.src_ip, dst=spec.dst_ip)
        tcp = scapy.TCP(sport=spec.src_port, dport=12345, seq=12345)
        payload = "meow"
        DEFAULT_TEMPLATE = str(eth/ip/tcp/payload)

        if spec.flow_rate is None:
            spec.flow_rate = spec.num_flows / spec.flow_duration

        tx_pipes = dict()
        rx_pipes = dict()

        num_cores = len(spec.cores)
        flows_per_core = spec.num_flows / num_cores

        if spec.pps is not None:
            pps_per_core = spec.pps / num_cores
        else:
            pps_per_core = 5e6

        if spec.mbps is not None:
            bps_per_core = long(1e6 * spec.mbps / num_cores)


        cli.bess.pause_all()
        for i, core in enumerate(spec.cores):
            cli.bess.add_worker(wid=core, core=core)
            src = FlowGen(template=DEFAULT_TEMPLATE, pps=pps_per_core,
                        flow_rate=flows_per_core, flow_duration=spec.flow_duration,
                        arrival=spec.arrival, duration=spec.duration,
                        quick_rampup=True)
            if spec.mbps is not None:
                rr_name, rl_name, leaf_name = create_rate_limit_tree(cli,
                                                                      core,
                                                                      'bit',
                                                                      bps_per_core)
                cli.bess.attach_task(src.name, tc=leaf_name)
            else:
                cli.bess.attach_task(src.name, 0, wid=core)

            # Setup tx pipeline
            tx_pipe = [src, IPChecksum(), Timestamp(), QueueOut(port=port, qid=i)]
            tx_pipes[core] = Pipeline(tx_pipe)

            # Setup rx pipeline
            rx_pipe = [QueueInc(port=port, qid=i), Measure(), Sink()]
            cli.bess.attach_task(rx_pipe[0].name, 0, wid=core)
            rx_pipes[core] = Pipeline(rx_pipe)
        cli.bess.resume_all()

        return (tx_pipes, rx_pipes)
