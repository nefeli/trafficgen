import os
import sys
import threading
import time

from module import *

THIS_DIR = os.path.dirname(os.path.realpath(__file__))
ADJUST_WINDOW_US = 1e6
ADJUST_FACTOR = 1.3
MAX_ROUNDS = 10

def time_ms():
    return time.time() * 1e3


def time_us():
    return time.time() * 1e6


def sleep_ms(dur):
    time.sleep(dur / 1e3)


def sleep_us(dur):
    time.sleep(dur / 1e6)


@staticmethod
def _choose_arg(arg, kwargs):
    if kwargs:
        if arg:
            raise TypeError('You cannot specify both arg and keyword args')

        for key in kwargs:
            if isinstance(kwargs[key], (Module,)):
                kwargs[key] = kwargs[key].name

        return kwargs

    if isinstance(arg, (Module,)):
        return arg.name
    else:
        return arg


def setup_mclasses(cli, globs):
    MCLASSES = [
        'FlowGen',
        'IPChecksum',
        'Measure',
        'Merge',
        'QueueInc',
        'QueueOut',
        'RandomUpdate',
        'Rewrite',
        'RoundRobin',
        'Source',
        'Sink',
        'Timestamp',
        'Update',
    ]
    for name in MCLASSES:
        if name in globals():
            break
        globs[name] = type(str(name), (Module,), {'bess': cli.bess,
                               'choose_arg': _choose_arg})


class Pipeline(object):
    def __init__(self, modules, tc=None):
        self.modules = modules
        self.tc = tc


class TrafficSpec(object):
    def __init__(self, loss_rate=None, pps=None, mbps=None,
                 tx_cores=None, rx_cores=None, src_mac='02:1e:67:9f:4d:bb',
                 dst_mac='02:1e:67:9f:4d:bb', src_ip='192.168.0.1',
                 dst_ip='10.0.0.1', tx_timestamp_offset=0,
                 rx_timestamp_offset=0):
        self.loss_rate = loss_rate
        self.pps = pps
        self.mbps = mbps
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.tx_cores = tx_cores
        self.rx_cores = rx_cores
        self.tx_timestamp_offset = tx_timestamp_offset
        self.rx_timestamp_offset = rx_timestamp_offset


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
        attrs = [
            ('loss_rate', lambda x: str(x) if x else 'disabled'),
            ('pps', lambda x: str(x) if x else '<= line rate'),
            ('mbps', lambda x: str(x) if x else '<= line rate'),
            ('src_mac', lambda x: x),
            ('dst_mac', lambda x: x),
            ('src_ip', lambda x: x),
            ('dst_ip', lambda x: x),
            ('tx_cores', lambda x: ','.join(map(str, x))),
            ('rx_cores', lambda x: ','.join(map(str, x)))
        ]
        return self._attrs_to_str(attrs, 25)

    def __repr__(self):
        return self.__str__()


class Session(object):
    """
    docstring
    """
    def __init__(self, port, spec, mode, tx_pipelines, rx_pipelines, bess, cli):
        now = time.time()
        self.__port = port
        self.__spec = spec
        self.__mode = mode
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
        self.__round = 0
        self.__bess = bess
        self.__cli = cli
        self.__stopmon = threading.Event()
        self.__monitor_thread = None

    def start_monitor(self):
        if self.__monitor_thread is None:
            self.__stopmon.clear()
            self.__monitor_thread = threading.Thread(target=self.monitor)
            self.__monitor_thread.start()

    def stop_monitor(self):
        if self.__monitor_thread is not None:
            self.__stopmon.set()
            self.__monitor_thread.join()

    def port(self):
        return self.__port

    def spec(self):
        return self.__spec

    def mode(self):
        return self.__mode

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

    def _sleep_or_quit(self, dur_us):
        start = time.time()
        while (time.time() - start) * 1e6 < dur_us:
            if self.__stopmon.is_set():
                return True
            sleep_ms(1)
        return False

    def _pause(self):
        with self.__cli.bess_lock:
            for core in self.__spec.tx_cores + self.__spec.rx_cores:
                self.__bess.pause_worker(core)

    def _resume(self):
        with self.__cli.bess_lock:
            for core in self.__spec.tx_cores + self.__spec.rx_cores:
                self.__bess.resume_worker(core)

    def monitor(self):
        """
        Thread to monitor ourselves until told to stop.
        """
        while not self.__stopmon:
            now = time.time()
            try:
                self.update_rtt()
                self.update_port_stats(now)

                self._pause()
                try:
                    self.adjust_tx_rate()
                finally:
                    self._resume()
            except bess.BESS.APIError:
                pass
            self._sleep_or_quit(ADJUST_WINDOW_US)

    # TODO: allow dynamic tx on mbps
    def adjust_tx_rate(self):
        if self.__spec.loss_rate is None or self.__spec.pps is None \
           or self.__round == MAX_ROUNDS:
            return

        delta_t = self.__now - self.__last_check
        # Count rx drops, too. We shouldn't penalize the DUT if we can't keep up
        pkts_in = (self.__curr_stats.inc.packets + \
                   self.__curr_stats.inc.dropped) - \
                  (self.__last_stats.inc.packets + \
                   self.__last_stats.inc.dropped)
        pkts_out = self.__curr_stats.out.packets - self.__last_stats.out.packets
        try:
            loss = ((pkts_out - pkts_in) * 100.0) / pkts_out
        except ZeroDivisionError:
            loss = 0.0

        if loss > self.__spec.loss_rate:
            self.__current_pps += pkts_in / float(delta_t)
            self.__current_pps /= 2
        else:
            self.__current_pps *= ADJUST_FACTOR
        self.__round += 1

        num_cores = len(self.__tx_pipelines.keys())
        pps_per_core = self.__current_pps / num_cores
        for core, tx_pipeline in self.__tx_pipelines.items():
            tc = tx_pipeline.tc 
            if tc is None:
                tx_pipeline.modules[0].update(pps=pps_per_core)
            else:
                with self.__cli.bess_lock:
                    self.__bess.update_tc_params(tc, resource='packet',
                                                 limit={'packet': long(pps_per_core)})

    def update_port_stats(self, now=None):
        if self.__last_stats is not None:
            self.__last_stats = self.__curr_stats
        self.__curr_stats = self.__bess.get_port_stats(self.__port)
        if self.__last_stats is None:
            self.__last_stats = self.__curr_stats
        self.__last_check = self.__now
        self.__now = now if now is not None else now()

    def _get_rtt(self):
        stats = {'rtt_avg': 0, 'rtt_med': 0, 'rtt_99': 0,
                 'jitter_avg': 0, 'jitter_med': 0, 'jitter_99': 0}
        for core, rx_pipeline in self.__rx_pipelines.items():
            now = rx_pipeline.modules[1].get_summary()
            stats['rtt_avg'] += now.latency_avg_ns
            stats['rtt_med'] += now.latency_50_ns
            stats['rtt_99'] += now.latency_99_ns
            stats['jitter_avg'] += now.jitter_avg_ns
            stats['jitter_med'] += now.jitter_50_ns
            stats['jitter_99'] += now.jitter_99_ns
        for k in stats:
            stats[k] /= len(self.__rx_pipelines.keys())
            stats[k] /= 1e3 # convert to us
        return stats

    def update_rtt(self):
        self.__bess.pause_all() # ???
        self.__curr_rtt = self._get_rtt()
        self.__bess.resume_all()
        self.__last_check = self.__now
