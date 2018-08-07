import os
import sys
import threading
import time

import pybess.bess
from pybess.module import *

THIS_DIR = os.path.dirname(os.path.realpath(__file__))

# How often, in seconds, monitor threads for non RFC2544 sessions should wake
# up to update statistics
MONITOR_PERIOD = 1

# Default RFC 2544 round duration in seconds
DEFAULT_2544_WINDOW = 30

# Default RFC 2544 warmup duration in seconds
DEFAULT_2544_WARMUP = 5

# Default RFC 2544 queue drain duration in seconds
DEFAULT_2544_DRAIN = 5

# Default RFC 2544 rate modifier percentage. Must be in [0, 100]
DEFAULT_2544_ADJ = 10

# Default RFC 2544 round limit.
DEFAULT_2544_MAX_ROUNDS = 10

RFC_2544_DEBUG = False


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
        'ArpBlast',
        'Bypass',
        'EtherEncap',
        'ExactMatch',
        'FlowGen',
        'HashLB',
        'IPChecksum',
        'IPEncap',
        'IPsecEncap',
        'IPsecDecap',
        'Measure',
        'Merge',
        'PortOut',
        'Queue',
        'PortOut',
        'QueueInc',
        'QueueOut',
        'RandomUpdate',
        'Rewrite',
        'RoundRobin',
        'SetMetadata',
        'Sink',
        'Source',
        'Timestamp',
        'Update',
        'VLANPop',
        'VLANPush',
        'VXLANDecap',
        'VXLANEncap',
    ]
    for name in MCLASSES:
        if name in globals():
            break
        globs[name] = type(str(name), (Module,), {'bess': cli.bess,
                                                  'choose_arg': _choose_arg})


class Producers(object):

    def __init__(self, children):
        self.__children = children

    def children(self):
        return self.__children

    def configure(self, cli, parent=None, wid=None):
        pass


class RoundRobinProducers(Producers):

    def __init__(self, producers):
        self.__producers = producers
        children = [m.name for m in producers]
        super(RoundRobinProducers, self).__init__(children)

    def configure(self, cli, parent=None, wid=None):
        if (parent is not None and wid is not None) or parent == wid:
            raise Exception('exactly one of `parent` or `wid` must be set')

        if parent is not None:
            root_tc = '{}_rr'.format(parent)
            cli.bess.add_tc(root_tc, parent=parent, policy='round_robin')
        elif wid is not None:
            root_tc = 'rr_c{}'.format(wid)
            cli.bess.add_tc(root_tc, wid=wid, policy='round_robin')

        for module in self.__producers:
            cli.bess.attach_task(module.name, parent=root_tc)


class WeightedProducers(Producers):

    def __init__(self, producers, resource='count'):
        self.__producers = producers
        self.__resource = resource
        children = producers.values()
        super(WeightedProducers, self).__init__(children)

    def configure(self, cli, parent=None, wid=None):
        if (parent is not None and wid is not None) or parent == wid:
            raise Exception('exactly one of `parent` or `wid` must be set')

        if parent is not None:
            root_tc = '{}_weighted'.format(parent)
            cli.bess.add_tc(root_tc, parent=parent, policy='weighted_fair',
                            resource=self.__resource)
        elif wid is not None:
            root_tc = 'weighted_c{}'.format(wid)
            cli.bess.add_tc(root_tc, wid=wid, policy='weighted_fair',
                            resource=self.__resource)

        for module, weight in self.__producers.items():
            cli.bess.attach_task(module.name, parent=root_tc, share=weight)


class PriorityProducers(Producers):

    def __init__(self, producers):
        self.__producers = producers
        self.__resource = resource
        children = producers.values()
        super(PriorityProducers, self).__init__(children)

    def configure(self, cli, parent=None, wid=None):
        if (parent is not None and wid is not None) or parent == wid:
            raise Exception('exactly one of `parent` or `wid` must be set')

        if parent is not None:
            root_tc = '{}_pri'.format(parent)
            cli.bess.add_tc(root_tc, parent=parent, policy='priority')
        elif wid is not None:
            root_tc = 'pri_c{}'.format(wid)
            cli.bess.add_tc(root_tc, wid=wid, policy='priority')

        for pri, module in self.__producers.items():
            cli.bess.attach_task(module.name, parent=root_tc, priority=pri)


class Pipeline(object):

    def __init__(self, internal_graph=None, periphery=None, producers=None):
        if internal_graph is not None:
            self.__internal_graph = internal_graph
            self.__modules = set([x[0] for x in internal_graph.keys()])
            self.add_modules([x[0] for x in internal_graph.values()])
        else:
            self.__modules = set()
            self.__internal_graph = dict()

        if periphery is not None:
            for mgs in periphery.values():
                self.add_modules([mg[0] for mg in mgs])
            self.__periphery = periphery
        else:
            self.__periphery = dict()

        self.__producers = producers
        self.tc = None
        self.tx_q = None
        self.tx_rr = None

    def add_module(self, module):
        self.__modules.add(module)

    def add_modules(self, modules):
        for m in modules:
            self.__modules.add(m)

    def add_edge(self, src, ogate, dst, igate):
        self.__modules.add(src)
        self.__modules.add(dst)
        self.__internal_graph[(src, ogate)] = (dst, igate)

    def add_peripheral_edge(self, ext_gate, dst, igate):
        self.__modules.add(dst)
        if ext_gate not in self.__periphery:
            self.__periphery[ext_gate] = list()
        self.__periphery[ext_gate].append((dst, igate))

    def modules(self):
        return self.__modules

    def get_module(self, name):
        for m in self.__modules:
            if m.name == name:
                return m
        return None

    def inernal_graph(self):
        return self.__internal_graph

    def periphery(self):
        return self.__periphery

    def producers(self):
        return self.__producers

    def set_producers(self, producers):
        self.__producers = producers

    def plumb(self):
        for src, dst in self.__internal_graph.items():
            src[0].connect(dst[0], src[1], dst[1])


class TrafficSpec(object):

    def __init__(self, pps=None, mbps=None,
                 tx_cores=None, rx_cores=None, src_mac=None,
                 dst_mac='02:1e:67:9f:4d:bb', src_ip='192.168.0.1',
                 dst_ip='10.0.0.1', tx_timestamp_offset=0,
                 rx_timestamp_offset=0,
                 ipsec=False,
                 rfc2544_loss_rate=None,
                 rfc2544_window=DEFAULT_2544_WINDOW,
                 rfc2544_warmup=DEFAULT_2544_WARMUP,
                 rfc2544_drain=DEFAULT_2544_DRAIN,
                 rfc2544_adj=DEFAULT_2544_ADJ,
                 rfc2544_max_rounds=DEFAULT_2544_MAX_ROUNDS):
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
        self.ipsec = ipsec
        self.rfc2544_loss_rate = rfc2544_loss_rate
        self.rfc2544_window = rfc2544_window
        self.rfc2544_warmup = rfc2544_warmup
        self.rfc2544_drain = rfc2544_drain
        self.rfc2544_adj = rfc2544_adj
        self.rfc2544_max_rounds = rfc2544_max_rounds

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
            ('rfc2544_loss_rate', lambda x: str(x) if x else 'disabled'),
            ('rfc2544_window', lambda x: x),
            ('rfc2544_warmup', lambda x: x),
            ('rfc2544_drain', lambda x: x),
            ('rfc2544_adj', lambda x: x),
            ('rfc2544_max_rounds', lambda x: x),
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

    def __init__(self, port, port_out, spec, mode, tx_pipelines, rx_pipelines, bess, cli):
        now = time.time()
        self.__port = port
        self.__port_out = port_out
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
        self.__successful_rounds = 0
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

    def port_out(self):
        return self.__port_out

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

    def _sleep_or_quit(self, dur):
        start = time.time()
        while (time.time() - start) < dur:
            if self.__stopmon.is_set():
                return True
            time.sleep(1e-3)
        return False

    def _pause(self):
        """
        Assuming the caller holds self.__cli.bess_lock
        """
        for core in self.__spec.tx_cores + self.__spec.rx_cores:
            self.__bess.pause_worker(core)

    def _resume(self):
        """
        Assuming the caller holds self.__cli.bess_lock
        """
        for core in self.__spec.tx_cores + self.__spec.rx_cores:
            self.__bess.resume_worker(core)

    def cli(self):
        return self.__cli

    def monitor(self):
        """
        Thread to monitor ourselves until told to stop.
        """
        while not self.__stopmon.is_set():
            if self.__spec.rfc2544_loss_rate is None:
                try:
                    with self.__cli.bess_lock:
                        self.update_rtt()
                        self.update_port_stats(time.time())
                except pybess.bess.BESS.APIError as e:
                    print(
                        'BESS API Error (port {}): {}'.format(self.__port, e))
                    pass
                except pybess.bess.BESS.Error as e:
                    print(
                        'Error fetching stats from BESS (port {}): {}'.format(self.__port, e))
                    pass
                time.sleep(MONITOR_PERIOD)
                continue

            try:
                with self.__cli.bess_lock:
                    self.update_rtt(True)

                    self._pause()
                    for core, tx_pipeline in self.__tx_pipelines.items():
                        if tx_pipeline.tx_rr is not None:
                            tx_pipeline.tx_rr.set_gates(gates=[0])
                    self._resume()
            except pybess.bess.BESS.APIError as e:
                print('BESS API Error (port {}): {}'.format(self.__port, e))
                pass
            except pybess.bess.BESS.Error as e:
                print(
                    'Error fetching stats from BESS (port {}): {}'.format(self.__port, e))
                pass

            if self._sleep_or_quit(self.__spec.rfc2544_warmup):
                break

            try:
                with self.__cli.bess_lock:
                    self.update_port_stats(time.time())
            except pybess.bess.BESS.APIError as e:
                print('BESS API Error (port {}): {}'.format(self.__port, e))
                pass
            except pybess.bess.BESS.Error as e:
                print(
                    'Error fetching stats from BESS (port {}): {}'.format(self.__port, e))
                pass

            if self._sleep_or_quit(self.__spec.rfc2544_window):
                break

            try:
                with self.__cli.bess_lock:
                    self.update_rtt()
                    self.update_port_stats(time.time())

                    self._pause()
                    self.adjust_tx_rate()
                    for core, tx_pipeline in self.__tx_pipelines.items():
                        if tx_pipeline.tx_rr is not None:
                            tx_pipeline.tx_rr.set_gates(gates=[1])
                    self._resume()
            except pybess.bess.BESS.APIError as e:
                print('BESS API Error (port {}): {}'.format(self.__port, e))
                pass
            except pybess.bess.BESS.Error as e:
                print(
                    'Error fetching stats from BESS (port {}): {}'.format(self.__port, e))
                pass

            if self._sleep_or_quit(self.__spec.rfc2544_drain):
                break

    def adjust_tx_rate(self):
        """
        Assuming the caller holds self.__cli.bess_lock
        """
        if self.__spec.rfc2544_loss_rate is None or self.__spec.pps is None \
           or self.__round == self.__spec.rfc2544_max_rounds:
            return

        delta_t = self.__now - self.__last_check
        # Count rx drops, too. We shouldn't penalize the DUT if we can't keep
        # up
        pkts_in = (self.__curr_stats.inc.packets +
                   self.__curr_stats.inc.dropped) - \
                  (self.__last_stats.inc.packets +
                   self.__last_stats.inc.dropped)
        pkts_out = self.__curr_stats.out.packets - \
            self.__last_stats.out.packets
        try:
            loss = ((pkts_out - pkts_in) * 100.0) / pkts_out
        except ZeroDivisionError:
            loss = 0.0

        self.__current_pps = min(self.__current_pps, pkts_out / delta_t)
        if RFC_2544_DEBUG:
            print('pkts_in: {}M, pkts_out: {}M, delta_t: {}, '
                  'pps_in: {}M, pps_out: {}M, config_pps: {}M, port: {}, '
                  'loss:{}, target: {}'.format(pkts_in / 1e6, pkts_out / 1e6,
                                               delta_t,
                                               pkts_in / delta_t /
                                               1e6, pkts_out / delta_t / 1e6,
                                               self.__current_pps / 1e6,
                                               self.__port, loss,
                                               self.__spec.rfc2544_loss_rate))

        if self.__successful_rounds >= 2:
            if RFC_2544_DEBUG:
                print('met target loss rate for two consecutive rounds at '
                      '{}Mpps'.format(self.__current_pps / 1e6))
            adj = (100 + self.__spec.rfc2544_adj) / 100.0
        elif loss > self.__spec.rfc2544_loss_rate:
            adj = (100 - self.__spec.rfc2544_adj) / 100.0
        else:
            self.__successful_rounds += 1
            return
        self.__successful_rounds = 0
        self.__current_pps *= adj
        self.__round += 1

        num_cores = len(self.__tx_pipelines.keys())
        pps_per_core = self.__current_pps / num_cores
        for core, tx_pipeline in self.__tx_pipelines.items():
            tc = tx_pipeline.tc
            if tc is None:
                tx_pipeline.modules[0].update(pps=pps_per_core)
            else:
                self.__bess.update_tc_params(tc, resource='packet',
                                             limit={'packet': long(pps_per_core)})

    def set_rate(self, rate, units):
        """
        Set the sending rate of this session.

        rate -- the new rate to use. must be >= 0
        units -- the units of `rate`. either 'pps' or 'bps'
        """
        resources = {'pps': 'packet', 'bps': 'bit'}
        if units not in resources:
            print('"units" must be one of "{}"'.format(
                ' '.join(resources.keys())))
            return
        resource = resources[units]

        with self.__cli.bess_lock:
            self._pause()
            num_cores = len(self.__tx_pipelines.keys())
            rate_per_core = rate / num_cores
            for core, tx_pipeline in self.__tx_pipelines.items():
                tc = tx_pipeline.tc
                if tc is None:
                    print('not supported')
                    return
                limit = {resource: long(rate_per_core)}
                self.__bess.update_tc_params(
                    tc, resource=resource, limit=limit)
            self._resume()

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
            measure = rx_pipeline.get_module(
                'trafficgen_measure_c{}'.format(core))
            now = measure.get_summary(clear=True,
                                      latency_percentiles=[50, 99],
                                      jitter_percentiles=[50, 99])
            stats['rtt_avg'] += now.latency.avg_ns
            stats['rtt_med'] += now.latency.percentile_values_ns[0]
            stats['rtt_99'] += now.latency.percentile_values_ns[1]
            stats['jitter_avg'] += now.jitter.avg_ns
            stats['jitter_med'] += now.jitter.percentile_values_ns[0]
            stats['jitter_99'] += now.jitter.percentile_values_ns[1]
        for k in stats:
            stats[k] /= len(self.__rx_pipelines.keys())
            stats[k] /= 1e3  # convert to us
        return stats

    def update_rtt(self, ignore=False):
        ret = self._get_rtt()
        if not ignore:
            self.__curr_rtt = ret
        self.__last_check = self.__now
