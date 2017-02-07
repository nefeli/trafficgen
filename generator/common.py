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


class TrafficSpec(object):
    def __init__(self, loss_rate=None, latency=False, pps=None):
        self.loss_rate = loss_rate
        self.latency = latency
        self.pps = pps


class UdpSpec(TrafficSpec):
    def __init__(self, pkt_size=60, num_flows=1, imix=False, **kwargs):
        self.pkt_size = pkt_size
        self.num_flows = num_flows
        self.imix = imix
        super(UdpSpec, self).__init__(**kwargs)


class HttpSpec(TrafficSpec):
    def __init__(self, num_flows=4000, src_mac='02:1e:67:9f:4d:aa',
                 dst_mac='02:1e:67:9f:4d:bb', src_ip='192.168.0.1',
                 dst_ip='10.0.0.1', src_port=1001, **kwargs):
        self.num_flows = num_flows
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        super(HttpSpec, self).__init__(**kwargs)


class FlowGenSpec(TrafficSpec):
    def __init__(self, pps=1e6, pkt_size=60, num_flows=10,
                 flow_duration=1, flow_rate=None, arrival='uniform',
                 duration='uniform', **kwargs):
        self.pkt_size = pkt_size
        self.num_flows = num_flows
        self.flow_duration = flow_duration
        self.flow_rate = flow_rate
        self.arrival = arrival
        self.duration = duration
        super(FlowGenSpec, self).__init__(**kwargs)


class Session(object):
    # TODO: need support for multiple cores
    def __init__(self, port, spec, tx_pipeline, rx_pipeline):
        now = time.time()
        self.__spec = spec
        self.__port = port
        self.__curr_stats = None
        self.__last_stats = None
        self.__now = now
        self.__last_check = now
        self.__tx_pipeline = tx_pipeline
        self.__rx_pipeline = rx_pipeline
        self.__current_pps = spec.pps

    def port(self):
        return self.__port

    def spec(self):
        return self.__spec

    def tx_pipeline(self):
        return self.__tx_pipeline

    def rx_pipeline(self):
        return self.__rx_pipeline

    def last_stats(self):
        return self.__last_stats

    def last_check(self):
        return self.__last_chck

    def adjust_tx_rate(self):
        if self.__spec.loss_rate is None or self.__spec.pps is None:
            return

        delta_t = self.__now - self.__last_check
        delta_pps = self.__curr_stats.inc.packets - \
                    self.__last_stats.inc.packets
        pps = delta_pps / delta_t
        thresh = self.__current_pps * (1 - self.__spec.loss_rate)
        if pps < thresh:
            # try sending at the average rate
            self.__current_pps += pps
            self.__current_pps /= 2
        elif pps > thresh:
            self.__current_pps *= ADJUST_FACTOR
        src = self.__tx_pipeline[0]
        if src.mclass == 'FlowGen': # TODO: generalize this
            src.update(pps=self.__current_pps)

    def update_stats(self, cli, now=None):
        if self.__last_stats is not None:
            self.__last_stats = self.__curr_stats
        self.__curr_stats = cli.bess.get_port_stats(self.__port)
        if self.__last_stats is None:
            self.__last_stats = self.__curr_stats
        self.__last_check = self.__now
        self.__now = now if now is not None else now()