import os
import os.path
import sys
import fnmatch
import socket
import fcntl
import errno
import glob
import re
import subprocess
import pprint
import copy
import time
import inspect
import traceback
import tempfile
import signal
import collections
import scapy.all as scapy

import commands as bess_commands
from module import *

from common import *

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


def setup_mclasses(cli):
    MCLASSES = [
        'FlowGen',
        'IPChecksum',
        'Measure',
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
        globals()[name] = type(str(name), (Module,), {'bess': cli.bess,
                               'choose_arg': _choose_arg})


def get_var_attrs(cli, var_token, partial_word):
    var_type = None
    var_desc = ''
    var_candidates = []

    try:
        if var_token == 'ENABLE_DISABLE':
            var_type = 'endis'
            var_desc = 'one or more worker IDs'
            var_candidates = ['enable', 'disable']

        elif var_token == '[BESSD_OPTS...]':
            var_type = 'opts'
            var_desc = 'bess daemon command-line options (see "bessd -h")'

        elif var_token == 'MODE':
            var_type = 'name'
            var_desc = 'which type of traffic to generate'
            try:
                var_candidates = ['flowgen', 'udp', 'http']
            except:
                pass

        elif var_token == 'PORT':
            var_type = 'portid'
            var_desc = 'a port identifier'

        elif var_token == 'PORT...':
            var_type = 'portid+'
            var_desc = 'a port identifier'

        elif var_token == '[TRAFFIC_SPEC...]':
            var_type = 'map'

    except socket.error as e:
        if e.errno in [errno.ECONNRESET, errno.EPIPE]:
            cli.bess.disconnect()
        else:
            raise

    except cli.bess.APIError:
        pass

    if var_type is None:
        return None
    else:
        return var_type, var_desc, var_candidates

# Return (head, tail)
#   head: consumed string portion
#   tail: the rest of input line
# You can assume that 'line == head + tail'
def split_var(cli, var_type, line):
    if var_type in ['name', 'filename', 'endis', 'int', 'portid']:
        pos = line.find(' ')
        if pos == -1:
            head = line
            tail = ''
        else:
            head = line[:pos]
            tail = line[pos:]

    elif var_type in ['wid+', 'name+', 'map', 'pyobj', 'opts', 'portid+']:
        head = line
        tail = ''

    else:
        raise cli.InternalError('type "%s" is undefined', var_type)

    return head, tail


def _parse_map(**kwargs):
    return kwargs


# Return (mapped_value, tail)
#   mapped_value: Python value/object from the consumed token(s)
#   tail: the rest of input line
def bind_var(cli, var_type, line):
    head, remainder = split_var(cli, var_type, line)

    # default behavior
    val = head

    if var_type == 'endis':
        if 'enable'.startswith(val):
            val = 'enable'
        elif 'disable'.startswith(val):
            val = 'disable'
        else:
            raise cli.BindError('"endis" must be either "enable" or "disable"')

    elif var_type == 'name':
        if re.match(r'^[_a-zA-Z][\w]*$', val) is None:
            raise cli.BindError('"name" must be [_a-zA-Z][_a-zA-Z0-9]*')

    elif var_type == 'name+':
        val = sorted(list(set(head.split())))  # collect unique items
        for name in val:
            if re.match(r'^[_a-zA-Z][\w]*$', name) is None:
                raise cli.BindError('"name" must be [_a-zA-Z][_a-zA-Z0-9]*')

    elif var_type == 'portid':
        if re.match(r'^[\d\.:]*$', val) is None:
            raise cli.BindError('"name" must be [.:0-9]*')

    elif var_type == 'portid+':
        val = sorted(list(set(head.split())))  # collect unique items
        for name in val:
            if re.match(r'^[\d\.:]*$', name) is None:
                raise cli.BindError('"name" must be [.:0-9]*')

    elif var_type == 'filename':
        if val.find('\0') >= 0:
            raise cli.BindError('Invalid filename')

    elif var_type == 'map':
        try:
            val = eval('_parse_map(%s)' % head)
        except:
            raise cli.BindError('"map" should be "key=val, key=val, ..."')

    elif var_type == 'pyobj':
        try:
            if head.strip() == '':
                val = None
            else:
                val = eval(head)
        except:
            raise cli.BindError(
                '"pyobj" should be an object in python syntax'
                ' (e.g., 42, "foo", ["hello", "world"], {"bar": "baz"})')

    elif var_type == 'opts':
        val = val.split()

    elif var_type == 'int':
        try:
            val = int(val)
        except Exception:
            raise cli.BindError('Expected an integer')

    return val, remainder


bessctl_cmds = [
    'monitor pipeline',
]

cmdlist = filter(lambda x: x[0] in bessctl_cmds, bess_commands.cmdlist)

def cmd(syntax, desc=''):
    def cmd_decorator(func):
        cmdlist.append((syntax, desc, func))
    return cmd_decorator


@cmd('help', 'List available commands')
def help(cli):
    for syntax, desc, _ in cmdlist:
        cli.fout.write('  %-50s%s\n' % (syntax, desc))


def _show_config(cli, port):
    sess = cli.get_session(port)
    cli.fout.write('Port %s\n' % (port,))
    divider = '-'*(4 + len(port)) + '\n'
    cli.fout.write(divider)
    cli.fout.write(str(sess.spec()) + '\n')
    cli.fout.write(divider)

def _show_configs(cli, ports):
    sorted(list(set(ports)))
    for port in ports:
        _show_config(cli, port)

@cmd('show config', 'Show the current confiugration of all ports')
def show_config_all(cli):
    _show_configs(cli, cli.ports())

@cmd('show config PORT...', 'Show the current confiugration of a port')
def show_config_all(cli, ports):
    _show_configs(cli, ports)


def _do_reset(cli):
    cli.clear_sessions()
    with cli.bess_lock:
        cli.bess.pause_all()
        cli.bess.reset_all()
        cli.bess.resume_all()

@cmd('reset', 'Reset trafficgen')
def reset(cli):
    bess_commands.warn(cli, 'Going to reset everything.', _do_reset)

PortRate = collections.namedtuple('PortRate',
                                  ['inc_packets', 'inc_dropped', 'inc_bytes',
                                   'rtt_avg', 'rtt_med', 'rtt_99',
                                   'out_packets', 'out_dropped', 'out_bytes'])

def _monitor_ports(cli, *ports):

    def get_delta(old, new):
        sec_diff = new['timestamp'] - old['timestamp']
        return PortRate(
            inc_packets = (new['inc_packets'] - old['inc_packets']) / sec_diff,
            inc_dropped = (new['inc_dropped'] - old['inc_dropped']) / sec_diff,
            inc_bytes = (new['inc_bytes'] - old['inc_bytes']) / sec_diff,
            rtt_avg = (new['avg'] + old['avg']) / 2,
            rtt_med = (new['med'] + old['med']) / 2,
            rtt_99 = (new['99'] + old['99']) / 2,
            out_packets = (new['out_packets'] - old['out_packets']) / sec_diff,
            out_dropped = (new['out_dropped'] - old['out_dropped']) / sec_diff,
            out_bytes = (new['out_bytes'] - old['out_bytes']) / sec_diff)

    def print_header(timestamp):
        cli.fout.write('\n')
        cli.fout.write('%-20s%14s%10s%10s%10s%10s%10s       %14s%10s%10s\n' %
                       (time.strftime('%X') + str(timestamp % 1)[1:8],
                        'INC     Mbps', 'Mpps', 'dropped',
                        'avg_rtt', 'med_rtt', '99_rtt',
                        'OUT     Mbps', 'Mpps', 'dropped'))

        cli.fout.write('%s\n' % ('-' * 126))

    def print_footer():
        cli.fout.write('%s\n' % ('-' * 126))

    def print_delta(port, delta):
        cli.fout.write('%-20s%14.1f%10.3f%10d%10.3f%10.3f%10.3f        %14.1f%10.3f%10d\n' %
                       (port,
                        (delta.inc_bytes + delta.inc_packets * 24) * 8 / 1e6,
                        delta.inc_packets / 1e6,
                        delta.inc_dropped,
                        delta.rtt_avg,
                        delta.rtt_med,
                        delta.rtt_99,
                        (delta.out_bytes + delta.out_packets * 24) * 8 / 1e6,
                        delta.out_packets / 1e6,
                        delta.out_dropped))

    def get_total(arr):
        total = copy.deepcopy(arr[0])
        for stat in arr[1:]:
            total['inc_packets'] += stat['inc_packets']
            total['inc_dropped'] += stat['inc_dropped']
            total['inc_bytes'] += stat['inc_bytes']
            total['avg'] += stat['avg']
            total['med'] += stat['med']
            total['99'] += stat['99']
            total['out_packets'] += stat['out_packets']
            total['out_dropped'] += stat['out_dropped']
            total['out_bytes'] += stat['out_bytes']
        return total

    def get_all_stats(cli, sess):
        stats = cli.bess.get_port_stats(sess.port())
        try:
            ret = {
                'inc_packets': stats.inc.packets,
                'out_packets': stats.out.packets,
                'inc_bytes': stats.inc.bytes,
                'out_bytes': stats.out.bytes,
                'inc_dropped': stats.inc.dropped,
                'out_dropped': stats.out.dropped,
            }
        except:
            ret = {
                'inc_packets': 0,
                'out_packets': 0,
                'inc_bytes': 0,
                'out_bytes': 0,
                'inc_dropped': 0,
                'out_dropped': 0,
            }
        rtt_now = sess.curr_rtt()
        if rtt_now is None:
            rtt_now = {'avg': 0, 'med': 0, '99': 0, 'timestamp': stats.timestamp}
        ret.update(rtt_now)
        return ret

    all_ports = sorted(cli.bess.list_ports().ports, key=lambda x: x.name)
    drivers = {}
    for port in all_ports:
        drivers[port.name] = port.driver

    if not ports:
        ports = [port.name for port in all_ports]
        if not ports:
            raise cli.CommandError('No port to monitor')

    cli.fout.write('Monitoring ports: %s\n' % ', '.join(ports))

    last = {}
    now = {}

    for port in ports:
        last[port] = get_all_stats(cli, cli.get_session(port))

    try:
        while True:
            time.sleep(1)

            for port in ports:
                sess = cli.get_session(port)
                now[port] = get_all_stats(cli, sess)

            print_header(now[port]['timestamp'])

            for port in ports:
                print_delta('%s/%s' % (port, drivers[port]),
                            get_delta(last[port], now[port]))

            print_footer()

            if len(ports) > 1:
                print_delta('Total', get_delta(
                        get_total(last.values()),
                        get_total(now.values())))

            for port in ports:
                last[port] = now[port]
    except KeyboardInterrupt:
        pass


@cmd('monitor port', 'Monitor the current traffic of all ports')
def monitor_port_all(cli):
    _monitor_ports(cli)


@cmd('monitor port PORT...', 'Monitor the current traffic of specified ports')
def monitor_port_all(cli, ports):
    _monitor_ports(cli, *ports)


def _connect_pipeline(cli, pipe):
    with cli.bess_lock:
        cli.bess.pause_all()
        for i in range(len(pipe)):
            u = pipe[i]
            if i < len(pipe) - 1:
                v =  pipe[i + 1]
                u.connect(v)
        cli.bess.resume_all()


def _create_rate_limit_tree(cli, wid, resource, limit):
    rr_name = 'rr_w%d' % (wid,)
    rl_name = 'rl_pps_w%d' % (wid,)
    leaf_name = 'bit_leaf_w%d' % (wid,)
    cli.bess.add_tc(rr_name, wid=wid, policy='round_robin', priority=0)
    cli.bess.add_tc(rl_name, parent=rr_name, policy='rate_limit',
                    resource=resource, limit={resource: limit})
    cli.bess.add_tc(leaf_name, policy='leaf', parent=rl_name)
    return (rr_name, rl_name, leaf_name)


"""
TRAFFIC_SPEC:
    loss_rate -- target percentage of packet loss (default 0.0)
    pps -- tx rate in pps
    pkt_size -- packet size
    num_flows -- number of flows
    flow_duration -- duration of each flows
    flow_rate -- flow arrival rate
    arrival -- distribution of flows (either 'uniform' or 'exponential')
    duration -- distribution of flow durations (either 'uniform' or 'pareto')
"""
def _start_flowgen(cli, port, spec):
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
        if spec.latency:
            rr_name, rl_name, leaf_name = _create_rate_limit_tree(cli,
                                                                  core,
                                                                  'bit',
                                                                  bps_per_core)
            cli.bess.attach_task(src.name, tc=leaf_name)
        else:
            cli.bess.attach_task(src.name, 0, wid=core)

        # Setup tx pipeline
        tx_pipe = [src, IPChecksum()]
        if spec.latency:
            tx_pipe.append(Timestamp())
        tx_pipe.append(QueueOut(port=port, qid=i))
        tx_pipes[core] = Pipeline(tx_pipe)

        # Setup rx pipeline
        rx_pipe = [QueueInc(port=port, qid=i)]
        if spec.latency:
            rx_pipe.append(Measure())
        rx_pipe.append(Sink())
        rx_pipes[core] = Pipeline(rx_pipe)
    cli.bess.resume_all()

    return (tx_pipes, rx_pipes)


def _build_pkt(spec, size):
    eth = scapy.Ether(src=spec.src_mac, dst=spec.dst_mac)
    ip = scapy.IP(src=spec.src_ip, dst=spec.dst_ip)
    udp = scapy.UDP(sport=10001, dport=10002, chksum=0)
    payload = ('hello' + '0123456789' * 200)[:size-len(eth/ip/udp)]
    pkt = eth/ip/udp/payload
    return str(pkt)

"""
TRAFFIC_SPEC:
    pkt_size -- packet size (default: 60)
    num_flows -- number of flows (default: 1)
    imix -- generate imix traffic if non-zero (default: 0)
    mbps -- max tx rate (default: 0 i.e., unlimited)
"""
def _start_udp(cli, port, spec):
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

    tx_pipes = dict()
    rx_pipes = dict()

    cli.bess.pause_all()

    num_cores = len(spec.cores)
    if spec.mbps is not None:
        bps_per_core = long(1e6 * spec.mbps / num_cores)
    elif spec.pps is not None:
        pps_per_core = long(spec.pps / num_cores)

    for i, core in enumerate(spec.cores):
        cli.bess.add_worker(wid=core, core=core)
        src = Source()
        if spec.mbps is not None:
            rr_name, rl_name, leaf_name = _create_rate_limit_tree(cli,
                                                                  core,
                                                                  'bit',
                                                                  bps_per_core)
            cli.bess.attach_task(src.name, tc=leaf_name)
        elif spec.pps is not None:
            rr_name, rl_name, leaf_name = _create_rate_limit_tree(cli,
                                                                  core,
                                                                  'packet',
                                                                  pps_per_core)
            cli.bess.attach_task(src.name, tc=leaf_name)
        else:
            rr_name = None
            rl_name = None
            leaf_name = None
            cli.bess.attach_task(src.name, 0, wid=core)

        # Setup tx pipeline
        tx_pipe = [
            src,
            Rewrite(templates=pkt_templates),
            RandomUpdate(fields=[{'offset': 30,
                                   'size': 4,
                                   'min': 0x0a000001,
                                   'max': 0x0a000001 + num_flows - 1}]),
            IPChecksum()
        ]
        if spec.latency:
            tx_pipe.append(Timestamp())
        tx_pipe.append(QueueOut(port=port, qid=i))
        tx_pipes[core] = Pipeline(tx_pipe, rl_name)

        # Setup rx pipeline
        rx_pipe = [QueueInc(port=port, qid=i)]
        cli.bess.attach_task(rx_pipe[0].name, 0, wid=core)
        if spec.latency:
            rx_pipe.append(Measure())
        rx_pipe.append(Sink())
        rx_pipes[core] = Pipeline(rx_pipe)

    cli.bess.resume_all()

    return (tx_pipes, rx_pipes)


"""
TRAFFIC_SPEC:
    num_flows -- number of flows
    src_mac -- source mac address
    dst_mac -- destination mac address
    src_ip -- start of source ip range
    dst_ip -- start of destination ip range
    src_port -- port to send http requests from
    cores -- a list of cores to use (defualt: "0")
"""
def _start_http(cli, port, spec):
    SEQNO = 12345
    PORT_HTTP = 80
    eth = scapy.Ether(src=spec.src_mac, dst=spec.dst_mac)
    ip = scapy.IP(src=spec.src_ip, dst=spec.dst_ip)
    tcp = scapy.TCP(sport=spec.src_port, dport=PORT_HTTP, seq=SEQNO)

    payload_prefix = 'GET /pub/WWW/TheProject.html HTTP/1.1\r\nHost: www.'
    payload = payload_prefix + 'aaa.com\r\n\r\n'
    pkt_headers = eth/ip/tcp
    pkt_template = str(eth/ip/tcp/payload)

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

        src = FlowGen(template=pkt_template, pps=pps_per_core,
                     flow_rate=flows_per_core, flow_duration=5,
                     arrival='uniform', duration='uniform', quick_rampup=False)
        if spec.latency:
            rr_name, rl_name, leaf_name = _create_rate_limit_tree(cli,
                                                                  core,
                                                                  'bit',
                                                                  bps_per_core)
            cli.bess.attach_task(src.name, tc=leaf_name)
        else:
            cli.bess.attach_task(src.name, 0, wid=core)

        # Setup tx pipeline
        tx_pipe = [
            src,
            RandomUpdate(fields=[{'offset': len(pkt_headers)  + len(payload_prefix),
                         'size': 1, 'min': 97, 'max': 122}]),
            RandomUpdate(fields=[{'offset': len(pkt_headers)  + \
                                            len(payload_prefix) + 1,
                                  'size': 1, 'min': 97, 'max': 122}]),
            IPChecksum(),
        ]
        if spec.latency:
            tx_pipe.append(Timestamp())
        tx_pipe.append(QueueOut(port=port, qid=i))
        tx_pipes[core] = Pipeline(tx_pipe)

        # Setup rx pipeline
        rx_pipe = [QueueInc(port=port, qid=i)]
        if spec.latency:
            rx_pipe.append(Measure())
        rx_pipe.append(Sink())
        rx_pipes[core] = Pipeline(rx_pipe)
    cli.bess.resume_all()

    return (tx_pipes, rx_pipes)


def _create_port_args(cli, port_id, num_cores):
    args = {'driver': None, 'name': port_id,
            'arg': {'num_inc_q': num_cores, 'num_out_q': num_cores}}
    args['driver'] = 'PMDPort'
    if re.match(r'^\d\d:\d\d.\d$', port_id) is not None:
        args['arg']['pci'] = port_id
    else:
        try:
            args['arg']['port_id'] = int(port_id)
        except:
            raise cli.CommandError('Invalid port index')
    return args


@cmd('start PORT MODE [TRAFFIC_SPEC...]', 'Start sending packets on a port')
def start(cli, port, mode, spec):
    setup_mclasses(cli)
    if not isinstance(port, str):
        raise cli.CommandError('Port identifier must be a string')

    if spec is not None and 'cores' in spec:
        cores = spec['cores'].split(' ')
    else:
        cores = [0]

    num_cores = len(cores)
    port_args = _create_port_args(cli, port, num_cores)
    with cli.bess_lock:
        ret = cli.bess.create_port(port_args['driver'], port_args['name'],
                                   arg=port_args['arg'])
        port = ret.name

    if spec is not None and 'src_mac' not in spec:
        spec['src_mac'] = ret.mac_addr

    if cli.port_is_running(port):
        raise cli.CommandError("Port %s is already running" % (port,))

    if mode == 'flowgen':
        if spec is not None:
            ts = FlowGenSpec(**spec)
        else:
            ts = FlowGenSpec(src_mac=ret.mac_addr)
        tx_pipes, rx_pipes = _start_flowgen(cli, port, spec=ts)
    elif mode == 'udp':
        if spec is not None:
            ts = UdpSpec(**spec)
        else:
            ts = UdpSpec(src_mac=ret.mac_addr)
        tx_pipes, rx_pipes = _start_udp(cli, port, spec=ts)
    elif mode == 'http':
        if spec is not None:
            ts = HttpSpec(**spec)
        else:
            ts = HttpSpec(src_mac=ret.mac_addr)
        tx_pipes, rx_pipes = _start_http(cli, port, spec=ts)

    for core, tx_pipe in tx_pipes.items():
        _connect_pipeline(cli, tx_pipe.modules)

    for core, rx_pipe in rx_pipes.items():
        _connect_pipeline(cli, rx_pipe.modules)

    cli.add_session(Session(port, ts, tx_pipes, rx_pipes))


@cmd('stop PORT...', 'Stop sending packets on a set of ports')
def stop(cli, ports):
    setup_mclasses(cli)
    sessions = []
    for port in ports:
        sessions.append(cli.remove_session(port))

    for sess in sessions:
        with cli.bess_lock:
            cli.bess.pause_all()
            try:
                for core, pipe in sess.tx_pipelines().items():
                    for m in pipe.modules:
                        cli.bess.destroy_module(m.name)

                for core, pipe in sess.rx_pipelines().items():
                    for m in pipe.modules:
                        cli.bess.destroy_module(m.name)
                    cli.bess.destroy_worker(core)

                cli.bess.destroy_port(sess.port())
            finally:
                cli.bess.resume_all()
