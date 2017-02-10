import os
import sys
import time

THIS_DIR = os.path.dirname(os.path.realpath(__file__))
ADJUST_FACTOR = 1.1
ADJUST_WINDOW_US = 1e6

def time_ms():
    return time.time() * 1e3


def time_us():
    return time.time() * 1e6


def sleep_ms(dur):
    time.sleep(dur / 1e3)


def sleep_us(dur):
    time.sleep(dur / 1e6)


class Pipeline(object):
    def __init__(self, modules, tc=None):
        self.modules = modules
        self.tc = tc


class TrafficSpec(object):
    def __init__(self, loss_rate=None, latency=False, pps=None, mbps=None,
                 cores=None, src_mac='02:1e:67:9f:4d:bb',
                 dst_mac='02:1e:67:9f:4d:bb', src_ip='192.168.0.1',
                 dst_ip='10.0.0.1'):
        self.loss_rate = loss_rate
        self.latency = latency
        self.pps = pps
        self.mbps = mbps
        if latency and self.mbps is None:
            self.mbps = 100
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.cores = cores


    """Print attribtues of an object in a two-column table of `width` characters

    Arguements:
        obj -- the object to print
        attrs -- a list of pairs (a, f). a is the attribute, f handles
                 converting that attribue to a string
        width -- row width in characters
    """
    def _attrs_to_str(self, attrs, width):
        lines = list()
        for a, f in attrs:
            val_len = width - len(a) + 2
            s = '%s: %%%ds' % (a, val_len)
            val = getattr(self, a)
            lines.append(s % f(val))
        return '\n'.join(lines)

    def __str__(self):
        ret = ''
        attrs = [
            ('loss_rate', lambda x: str(x) if x else 'disabled'),
            ('latency', lambda x: 'true' if x else 'false'),
            ('pps', lambda x: str(x) if x else '<= line rate'),
            ('mbps', lambda x: str(x) if x else '<= line rate'),
            ('src_mac', lambda x: x),
            ('dst_mac', lambda x: x),
            ('src_ip', lambda x: x),
            ('dst_ip', lambda x: x),
            ('cores', lambda x: ','.join(map(str, x)))
        ]
        return self._attrs_to_str(attrs, 25)

    def __repr__(self):
        return self.__str__()


class UdpSpec(TrafficSpec):
    def __init__(self, pkt_size=60, num_flows=1, imix=False, **kwargs):
        self.pkt_size = pkt_size
        self.num_flows = num_flows
        self.imix = imix
        super(UdpSpec, self).__init__(**kwargs)

    def __str__(self):
        s = super(UdpSpec, self).__str__() + '\n'
        attrs = [
            ('pkt_size', lambda x: str(x)),
            ('num_flows', lambda x: str(x)),
            ('imix', lambda x: 'enabled' if x else 'disabled')
        ]
        return s + self._attrs_to_str(attrs, 25)

    def __repr__(self):
        return self.__str__()


class HttpSpec(TrafficSpec):
    def __init__(self, num_flows=4000, src_port=1001, **kwargs):
        self.num_flows = num_flows
        self.src_port = src_port
        super(HttpSpec, self).__init__(**kwargs)

    def __str__(self):
        s = super(HttpSpec, self).__str__() + '\n'
        attrs = [
            ('num_flows', lambda x: str(x)),
            ('src_port', lambda x: str(x)),
        ]
        return s + self._attrs_to_str(attrs, 25)

    def __repr__(self):
        return self.__str__()


class FlowGenSpec(TrafficSpec):
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
        super(FlowGenSpec, self).__init__(**kwargs)

    def __str__(self):
        s = super(FlowGenSpec, self).__str__() + '\n'
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


class Session(object):
    def __init__(self, port, spec, tx_pipelines, rx_pipelines):
        now = time.time()
        self.__spec = spec
        self.__port = port
        self.__curr_stats = None
        self.__last_stats = None
        """
        `__curr_rtt` stores the average of the rtt measurements
        from each worker associated to this session. 
        """
        self.__curr_rtt = None
        self.__now = now
        self.__last_check = now
        """
        `__tx_pipelines` and `__rx_pipelines` map cores to pipelines e.g.,
        `__tx_pipelines` might look like  {0: Pipeline([FlowGen(), Sink()])}
        for a simple flowgen pipeline
        """
        self.__tx_pipelines = tx_pipelines
        self.__rx_pipelines = rx_pipelines
        self.__current_pps = spec.pps

    def port(self):
        return self.__port

    def spec(self):
        return self.__spec

    def tx_pipelines(self):
        return self.__tx_pipelines

    def rx_pipelines(self):
        return self.__rx_pipelines

    def last_stats(self):
        return self.__last_stats

    def curr_stats(self):
        return self.__curr_stats

    def curr_rtt(self):
        return self.__curr_rtt

    def last_check(self):
        return self.__last_chck

    # TODO: allow dynamic tx on mbps
    def adjust_tx_rate(self, cli):
        if self.__spec.loss_rate is None or self.__spec.pps is None:
            return

        delta_t = self.__now - self.__last_check
        pkts_in = self.__curr_stats.inc.packets - self.__last_stats.inc.packets
        pkts_out = self.__curr_stats.out.packets - self.__last_stats.out.packets
        try:
            loss = ((pkts_out - pkts_in) * 100.0) / pkts_out
        except ZeroDivisionError:
            loss = 0.0

        if loss > self.__spec.loss_rate:
            self.__current_pps *= pkts_in / float(pkts_out)
        else:
            self.__current_pps *= ADJUST_FACTOR

        num_cores = len(self.__tx_pipelines.keys())
        pps_per_core = self.__current_pps / num_cores
        for core, tx_pipeline in self.__tx_pipelines.items():
            tc = tx_pipeline.tc 
            if tc is None:
                tx_pipeline.modules[0].update(pps=pps_per_core)
            else:
                cli.bess.update_tc(tc, resource='packet',
                               limit={'packet': long(pps_per_core)})

    def update_port_stats(self, cli, now=None):
        if self.__last_stats is not None:
            self.__last_stats = self.__curr_stats
        self.__curr_stats = cli.bess.get_port_stats(self.__port)
        if self.__last_stats is None:
            self.__last_stats = self.__curr_stats
        self.__last_check = self.__now
        self.__now = now if now is not None else now()

    def _get_rtt(self):
        stats = {'avg': 0, 'med': 0, '99': 0, 'timestamp': 0}
        for core, rx_pipeline in self.__rx_pipelines.items():
            now = rx_pipeline.modules[1].get_summary()
            stats['avg'] += now.latency_avg_ns
            stats['med'] += now.latency_50_ns
            stats['99'] += now.latency_99_ns
            stats['timestamp'] = now.timestamp
        for k in stats:
            if k == 'timestamp': continue
            stats[k] /= len(self.__rx_pipelines.keys())
            stats[k] /= 1e3 # convert to us
        return stats

    def update_rtt(self, cli):
        cli.bess.pause_all()
        self.__curr_rtt = self._get_rtt()
        cli.bess.resume_all()
        self.__last_check = self.__now
