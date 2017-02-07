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
        'QueueInc',
        'QueueOut',
        'Sink',
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
@cmd('start PORT [TRAFFIC_SPEC...]', 'Start sending packets on a port')
def start(cli, port, spec):
    setup_mclasses(cli)
    if cli.port_is_running(port):
        return cli.CommandError("Port %s is already running" % (port,))

    if spec is not None:
        pprint.pprint(spec)
        ts = TrafficSpec(**spec)
    else:
        ts = TrafficSpec()

    if ts.flow_rate is None:
        ts.flow_rate = ts.num_flows / ts.flow_duration

    with cli.bess_lock:
        cli.bess.pause_all()
        f = FlowGen(template=DEFAULT_TEMPLATE, pps=ts.pps,
                    flow_rate=ts.flow_rate, flow_duration=ts.flow_duration,
                    arrival=ts.arrival, duration=ts.duration, quick_rampup=True)
        qo = QueueOut(port=port, qid=0)
        qi = QueueInc(port=port, name='qinc_%s' % (port,), qid=0)
        sn = Sink()
        cli.bess.connect_modules(f.name, qo.name)
        cli.bess.connect_modules(qi.name, sn.name)
        cli.bess.resume_all()

    cli.add_session(Session(port, ts, [f, qo], [qi, sn]))


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
