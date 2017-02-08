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
        'QueueInc',
        'QueueOut',
        'RandomUpdate',
        'Rewrite',
        'RoundRobin',
        'Source',
        'Sink',
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

        elif var_token == 'DRIVER':
            var_type = 'name'
            var_desc = 'name of a port driver'
            try:
                var_candidates = cli.bess.list_drivers().driver_names
            except:
                pass

        elif var_token == '[NEW_PORT]':
            var_type = 'name'
            var_desc = 'specify a name of the new port'

        elif var_token == '[PORT_ARGS...]':
            var_type = 'map'

        elif var_token == 'MODE':
            var_type = 'name'
            var_desc = 'which type of traffic to generate'
            try:
                var_candidates = ['flowgen', 'udp', 'http']
            except:
                pass

        elif var_token == 'PORT':
            var_type = 'name'
            var_desc = 'name of a port'
            try:
                var_candidates = [p.name for p in cli.bess.list_ports().ports]
            except:
                pass

        elif var_token == 'PORT...':
            var_type = 'name+'
            var_desc = 'one or more port names'
            try:
                var_candidates = [p.name for p in cli.bess.list_ports().ports]
            except:
                pass

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
    if var_type in ['name', 'filename', 'endis', 'int']:
        pos = line.find(' ')
        if pos == -1:
            head = line
            tail = ''
        else:
            head = line[:pos]
            tail = line[pos:]

    elif var_type in ['wid+', 'name+', 'map', 'pyobj', 'opts']:
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
    'monitor port',
    'daemon reset',
    'daemon start [BESSD_OPTS...]',
    'daemon stop',
    'daemon connect',
    'daemon disconnect',
    'add port DRIVER [NEW_PORT] [PORT_ARGS...]',
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


def _connect_pipeline(cli, pipe):
    with cli.bess_lock:
        cli.bess.pause_all()
        for i in range(len(pipe)):
            u = pipe[i]
            if i < len(pipe) - 1:
                v =  pipe[i + 1]
                cli.bess.connect_modules(u.name, v.name)
        cli.bess.resume_all()


src_ether='02:1e:67:9f:4d:aa'
dst_ether='02:1e:67:9f:4d:bb'
eth = scapy.Ether(src=src_ether, dst=dst_ether)
src_ip='10.0.0.1'
dst_ip='192.0.0.1'
ip = scapy.IP(src=src_ip, dst=dst_ip)
src_port = 10001
tcp = scapy.TCP(sport=src_port, dport=12345, seq=12345)
payload = "meow"
DEFAULT_TEMPLATE = str(eth/ip/tcp/payload)

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
    if spec.flow_rate is None:
        spec.flow_rate = spec.num_flows / spec.flow_duration

    tx_pipes = dict()
    rx_pipes = dict()

    flows_per_core = spec.num_flows / len(spec.cores)
    pps_per_core = spec.pps / len(spec.cores)
    cli.bess.pause_all()
    for i, core in enumerate(spec.cores):
        cli.bess.add_worker(wid=core, core=core)
        src = FlowGen(template=DEFAULT_TEMPLATE, pps=pps_per_core,
                    flow_rate=flows_per_core, flow_duration=spec.flow_duration,
                    arrival=spec.arrival, duration=spec.duration,
                    quick_rampup=True)
        cli.bess.attach_task(src.name, 0, wid=core)
        tx_pipes[core] = Pipeline([src, QueueOut(port=port, qid=i)])

        rx_pipes[core] = Pipeline([QueueInc(port=port, qid=i), Sink()])
    cli.bess.resume_all()

    return (tx_pipes, rx_pipes)


def _build_pkt(size):
    eth = scapy.Ether(src='02:1e:67:9f:4d:ae', dst='06:16:3e:1b:72:32')
    ip = scapy.IP(src='192.168.0.1', dst='10.0.0.1')
    udp = scapy.UDP(sport=10001, dport=10002, chksum=0)
    payload = ('hello' + '0123456789' * 200)[:size-len(eth/ip/udp)]
    pkt = eth/ip/udp/payload
    pkt.show()
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
            _build_pkt(60),
            _build_pkt(60),
            _build_pkt(60),
            _build_pkt(60),
            _build_pkt(60),
            _build_pkt(60),
            _build_pkt(60),
            _build_pkt(590),
            _build_pkt(590),
            _build_pkt(590),
            _build_pkt(1514)
        ]
    else:
        pkt_templates = [_build_pkt(spec.pkt_size)]

    num_flows = spec.num_flows

    tx_pipes = dict()
    rx_pipes = dict()

    cli.bess.pause_all()

    num_cores = len(spec.cores)
    if spec.pps is not None:
        pps_per_core = long(spec.pps / num_cores)

    for i, core in enumerate(spec.cores):
        cli.bess.add_worker(wid=core, core=core)
        src = Source()
        if spec.pps is not None:
            rr_name = 'rr_w%d' % (core,)
            rl_name = 'rl_pps_w%d' % (core,)
            leaf_name = 'bit_leaf_w%d' % (core,)
            cli.bess.add_tc(rr_name, wid=core, policy='round_robin', priority=0)
            cli.bess.add_tc(rl_name, parent=rr_name, policy='rate_limit',
                            resource='packet', limit={'packet': pps_per_core})
            cli.bess.add_tc(leaf_name, policy='leaf', parent=rl_name)
            cli.bess.attach_task(src.name, tc=leaf_name)
        else:
            rr_name = None
            rl_name = None
            leaf_name = None
            cli.bess.attach_task(src.name, 0, wid=core)
        tx_pipes[core] = Pipeline([
            src,
            Rewrite(templates=pkt_templates),
            RandomUpdate(fields=[{'offset': 30,
                                   'size': 4,
                                   'min': 0x0a000001,
                                   'max': 0x0a000001 + num_flows - 1}]),
            IPChecksum(),
            QueueOut(port=port, qid=i)
        ], rl_name)

        rx_pipes[core] = Pipeline([QueueInc(port=port, qid=i), Sink()])
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

    flows_per_core = spec.num_flows / len(spec.cores)
    pps_per_core = spec.pps / len(spec.cores)
    cli.bess.pause_all()
    for i, core in enumerate(spec.cores):
        cli.bess.add_worker(wid=core, core=core)

        src = FlowGen(template=pkt_template, pps=pps_per_core,
                     flow_rate=flows_per_core, flow_duration=5,
                     arrival='uniform', duration='uniform', quick_rampup=False)
        cli.bess.attach_task(src.name, 0, wid=core)
        tx_pipes[core] = Pipeline([
            src,
            RandomUpdate(fields=[{'offset': len(pkt_headers)  + len(payload_prefix),
                         'size': 1, 'min': 97, 'max': 122}]),
            RandomUpdate(fields=[{'offset': len(pkt_headers)  + \
                                            len(payload_prefix) + 1,
                                  'size': 1, 'min': 97, 'max': 122}]),
            IPChecksum(),
            QueueOut(port=port, qid=i)
        ])

        rx_pipes[core] = Pipeline([QueueInc(port=port, qid=i), Sink()])
    cli.bess.resume_all()

    return (tx_pipes, rx_pipes)


@cmd('start PORT MODE [TRAFFIC_SPEC...]', 'Start sending packets on a port')
def start(cli, port, mode, spec):
    setup_mclasses(cli)
    if cli.port_is_running(port):
        return cli.CommandError("Port %s is already running" % (port,))

    if mode == 'flowgen':
        if spec is not None:
            ts = FlowGenSpec(**spec)
        else:
            ts = FlowGenSpec()
        tx_pipes, rx_pipes = _start_flowgen(cli, port, spec=ts)
    elif mode == 'udp':
        if spec is not None:
            ts = UdpSpec(**spec)
        else:
            ts = UdpSpec()
        tx_pipes, rx_pipes = _start_udp(cli, port, spec=ts)
    elif mode == 'http':
        if spec is not None:
            ts = HttpSpec(**spec)
        else:
            ts = HttpSpec()
        tx_pipes, rx_pipes = _start_http(cli, port, spec=ts)

    for core, tx_pipe in tx_pipes.items():
        _connect_pipeline(cli, tx_pipe.modules)

    for core, rx_pipe in rx_pipes.items():
        _connect_pipeline(cli, rx_pipe.modules)

    cli.add_session(Session(port, ts, tx_pipes, rx_pipes))


@cmd('stop PORT...', 'Stop sending packets on a set of ports')
def stop(cli, ports):
    setup_mclasses(cli)
    for port in ports:
        sess = cli.remove_session(port)
        with cli.bess_lock:
            cli.bess.pause_all()
            try:
                for m in sess.tx_pipeline():
                    cli.bess.destroy_module(m.name)
                for m in sess.rx_pipeline():
                    cli.bess.destroy_module(m.name)
            finally:
                cli.bess.resume_all()
