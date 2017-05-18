import collections
import copy
import errno
import fcntl
import fnmatch
import glob
import inspect
import multiprocessing
import os
import os.path
import pprint
import re
import scapy.all as scapy
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback

import commands as bess_commands
from pybess.module import *

from common import *
import modes

available_cores = list(range(multiprocessing.cpu_count()))

DEFAULT_STATS_CSV = '/tmp/bench.csv'
stats_csv = DEFAULT_STATS_CSV


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

        elif var_token == 'CSV':
            var_type = 'filename'
            var_desc = 'a path to a csv file'

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
    divider = '-' * (4 + len(port)) + '\n'
    cli.fout.write(divider)
    cli.fout.write('mode: %23s\n' % (sess.mode(),))
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
    for port in cli.ports():
        _stop(cli, port)

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
                                   'jitter_avg', 'jitter_med', 'jitter_99',
                                   'out_packets', 'out_dropped', 'out_bytes'])


def _monitor_ports(cli, *ports):
    global stats_csv

    def get_delta(old, new):
        sec_diff = new['timestamp'] - old['timestamp']
        return PortRate(
            inc_packets=(new['inc_packets'] - old['inc_packets']) / sec_diff,
            inc_dropped=(new['inc_dropped'] - old['inc_dropped']) / sec_diff,
            inc_bytes=(new['inc_bytes'] - old['inc_bytes']) / sec_diff,
            rtt_avg=(new['rtt_avg'] + old['rtt_avg']) / 2,
            rtt_med=(new['rtt_med'] + old['rtt_med']) / 2,
            rtt_99=(new['rtt_99'] + old['rtt_99']) / 2,
            jitter_avg=(new['jitter_avg'] + old['jitter_avg']) / 2,
            jitter_med=(new['jitter_med'] + old['jitter_med']) / 2,
            jitter_99=(new['jitter_99'] + old['jitter_99']) / 2,
            out_packets=(new['out_packets'] - old['out_packets']) / sec_diff,
            out_dropped=(new['out_dropped'] - old['out_dropped']) / sec_diff,
            out_bytes=(new['out_bytes'] - old['out_bytes']) / sec_diff)

    def print_header(timestamp):
        cli.fout.write('\n')
        cli.fout.write('%-20s%14s%10s%10s%15s%15s%15s%15s%15s%15s       %14s%10s%10s\n' %
                       (time.strftime('%X') + str(timestamp % 1)[1:8],
                        'INC     Mbps', 'Mpps', 'dropped',
                        'Avg RTT (us)', 'Med RTT (us)', '99th RTT (us)',
                        'Avg Jit (us)', 'Med Jit (us)', '99th Jit (us)',
                        'OUT     Mbps', 'Mpps', 'dropped'))

        cli.fout.write('%s\n' % ('-' * 186))

    def print_footer():
        cli.fout.write('%s\n' % ('-' * 186))

    def print_delta(port, delta, timestamp):
        stats = (port,
                 (delta.inc_bytes + delta.inc_packets * 24) * 8 / 1e6,
                 delta.inc_packets / 1e6,
                 delta.inc_dropped,
                 delta.rtt_avg,
                 delta.rtt_med,
                 delta.rtt_99,
                 delta.jitter_avg,
                 delta.jitter_med,
                 delta.jitter_99,
                 (delta.out_bytes + delta.out_packets * 24) * 8 / 1e6,
                 delta.out_packets / 1e6,
                 delta.out_dropped)
        cli.fout.write('%-20s%14.1f%10.3f%10d%15.3f%15.3f%15.3f%15.3f%15.3f%15.3f        '
                       '%14.1f%10.3f%10d\n' % stats)

        with open(stats_csv, 'a+') as f:
            line = '%s,%s,%.1f,%.3f,%d,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.1f,%.3f,%d\n'
            line %= (time.strftime('%X') + str(timestamp % 1)[1:8],) + stats
            f.write(line)

    def get_total(arr):
        total = copy.deepcopy(arr[0])
        for stat in arr[1:]:
            total['inc_packets'] += stat['inc_packets']
            total['inc_dropped'] += stat['inc_dropped']
            total['inc_bytes'] += stat['inc_bytes']
            total['rtt_avg'] += stat['rtt_avg']
            total['rtt_med'] += stat['rtt_med']
            total['rtt_99'] += stat['rtt_99']
            total['jitter_avg'] += stat['jitter_avg']
            total['jitter_med'] += stat['jitter_med']
            total['jitter_99'] += stat['jitter_99']
            total['out_packets'] += stat['out_packets']
            total['out_dropped'] += stat['out_dropped']
            total['out_bytes'] += stat['out_bytes']
        return total

    def get_all_stats(cli, sess, port):
        in_stats = cli.bess.get_port_stats(sess.rx_port())
        out_stats = cli.bess.get_port_stats(sess.tx_port())
        try:
            ret = {
                'inc_packets': in_stats.inc.packets,
                'out_packets': out_stats.out.packets,
                'inc_bytes': in_stats.inc.bytes,
                'out_bytes': out_stats.out.bytes,
                'inc_dropped': in_stats.inc.dropped,
                'out_dropped': out_stats.out.dropped,
                'timestamp': in_stats.timestamp,
            }
        except:
            ret = {
                'inc_packets': 0,
                'out_packets': 0,
                'inc_bytes': 0,
                'out_bytes': 0,
                'inc_dropped': 0,
                'out_dropped': 0,
                'timestamp': time.time(),
            }
        rtt_now = sess.curr_rtt()
        if rtt_now is None:
            rtt_now = {'rtt_avg': 0, 'rtt_med': 0, 'rtt_99': 0,
                       'jitter_avg': 0, 'jitter_med': 0, 'jitter_99': 0}
        ret.update(rtt_now)
        return ret

    if not ports:
        ports = sorted(cli.ports())

    if not ports:
        raise cli.CommandError('No port to monitor')

    cli.fout.write('Monitoring ports: %s (Send CTRL + c to stop)\n' %
                   ', '.join(ports))

    last = {}
    now = {}

    csv_header = '#' + ','.join(['time', 'port',
                                 'inc_mbps', 'inc_mpps', 'inc_dropped',
                                 'avg_rtt_us', 'med_rtt_us', '99th_rtt_us',
                                 'avg_jit_us', 'med_jit_us', '99th_jit_us',
                                 'out_mbps', 'out_mpps', 'out_dropped']) + '\n'

    with open(stats_csv, 'w+') as f:
        for port in ports:
            line = '#port ' + port + ': '
            line += str(cli.get_session(port).spec()).replace('\n', '; ')
            line = re.sub('\s+', ' ', line) + '\n'
            f.write(line)
        f.write(csv_header)

    for port in ports:
        sess = cli.get_session(port)
        last[port] = get_all_stats(cli, sess, port)

    try:
        while True:
            time.sleep(1)

            for port in ports:
                sess = cli.get_session(port)
                now[port] = get_all_stats(cli, sess, port)

            print_header(now[port]['timestamp'])

            for port in ports:
                sess = cli.get_session(port)
                if sess.tx_port() == sess.rx_port():
                    label = 'Session: %s' % (sess.tx_port(),)
                else:
                    label = 'Session: %s -> %s' % (sess.tx_port(), sess.rx_port())
                print_delta(label,
                            get_delta(last[port], now[port]),
                            now[port]['timestamp'])

            print_footer()

            if len(ports) > 1:
                print_delta('Total', get_delta(
                    get_total(last.values()),
                        get_total(now.values())),
                    now[port]['timestamp'])

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


@cmd('set csv CSV', 'Set the CSV file for stats output')
def set_csv(cli, csv):
    global stats_csv
    stats_csv = csv


def _connect_pipeline(cli, pipe):
    for i in range(len(pipe)):
        u = pipe[i]
        if i < len(pipe) - 1:
            v = pipe[i + 1]
            u[0].connect(v[0], u[1], v[1])


def _create_rate_limit_tree(cli, wid, resource, limit):
    rl_name = 'rl_pps_w%d' % (wid,)
    cli.bess.add_tc(rl_name, wid=wid, policy='rate_limit',
                    resource=resource, limit={resource: limit})
    return rl_name


def _create_port_args(cli, port_id, num_rx_cores, num_tx_cores):
    args = {'driver': None, 'name': port_id,
            'arg': {'num_inc_q': num_rx_cores, 'num_out_q': num_tx_cores,
                    'size_inc_q': 2048, 'size_out_q': 2048}}
    args['driver'] = 'PMDPort'
    if re.match(r'^\d\d:\d\d.\d$', port_id) is not None:
        args['arg']['pci'] = port_id
    else:
        try:
            args['arg']['port_id'] = int(port_id)
        except:
            raise cli.CommandError('Invalid port index')
    return args


@cmd('start PORT -> PORT MODE [TRAFFIC_SPEC...]', 'Start sending packets on a port')
def start(cli, tx_port, rx_port, mode, spec):
    setup_mclasses(cli, globals())
    global available_cores
    if not isinstance(tx_port, str) or not isinstance(rx_port, str):
        raise cli.CommandError('Port identifiers must be a strings')

    if cli.port_is_running(tx_port):
        bess_commands.warn(cli, 'Port %s is already running.' % (tx_port,),
                           _stop, tx_port)

    if cli.port_is_running(rx_port):
        bess_commands.warn(cli, 'Port %s is already running.' % (rx_port,),
                           _stop, rx_port)

    # Allocate cores if necessary
    if spec is not None:
        if 'tx_cores' in spec:
            tx_cores = list(map(int, spec.pop('tx_cores').split(' ')))
        else:
            if len(available_cores) > 0:
                tx_cores = [available_cores.pop(0)]
            else:
                raise cli.InternalError('No available cores.')

        if 'rx_cores' in spec:
            rx_cores = list(map(int, spec.pop('rx_cores').split(' ')))
        elif 'rx_cores' not in spec and 'tx_cores' not in spec:
            rx_cores = tx_cores
        else:
            if len(available_cores) > 0:
                rx_cores = [available_cores.pop(0)]
            else:
                raise cli.InternalError('No available cores.')
    else:
        if len(available_cores) > 0:
            tx_cores = [available_cores.pop(0)]
            rx_cores = tx_cores
        else:
            raise cli.InternalError('No available cores.')

    # Create the port
    num_tx_cores = len(tx_cores)
    num_rx_cores = len(rx_cores)
    num_cores = num_tx_cores + num_rx_cores
    tx_port_args = _create_port_args(cli, tx_port, num_tx_cores, num_rx_cores)
    rx_port_args = _create_port_args(cli, rx_port, num_tx_cores, num_rx_cores)
    with cli.bess_lock:
        ret = cli.bess.create_port(
            tx_port_args['driver'], tx_port_args['name'],
                                   arg=tx_port_args['arg'])
        tx_port = ret.name
        if rx_port != tx_port:
            ret = cli.bess.create_port(
                rx_port_args['driver'], rx_port_args['name'],
                                       arg=rx_port_args['arg'])
            rx_port = ret.name
        else:
            rx_port = tx_port

    if spec is not None and 'src_mac' not in spec:
        spec['src_mac'] = ret.mac_addr

    # Find traffic mode
    tmode = None
    for x in modes.__dict__:
        m = modes.__dict__[x]
        if getattr(m, 'name', '') == mode:
            tmode = m

    if tmode is None:
        raise cli.CommandError("Mode %s is invalid" % (mode,))

    # Initialize the pipelines
    if spec is not None:
        ts = tmode.Spec(tx_cores=tx_cores, rx_cores=rx_cores, **spec)
    else:
        ts = tmode.Spec(src_mac=ret.mac_addr, tx_cores=tx_cores,
                        rx_cores=rx_cores)

    tx_pipes = dict()
    rx_pipes = dict()

    with cli.bess_lock:
        cli.bess.pause_all()

        # Setup TX pipelines
        for i, core in enumerate(tx_cores):
            cli.bess.add_worker(wid=core, core=core, scheduler='experimental')
            tx_pipe = tmode.setup_tx_pipeline(cli, tx_port, ts)

            # These modules are required across all pipelines
            tx_pipe.tx_rr = RoundRobin(gates=[0])
            tx_pipe.tx_q = Queue()
            out_modules = [tx_pipe.tx_q,
                           Timestamp(offset=ts.tx_timestamp_offset),
                           tx_pipe.tx_rr]
            out_zipped = zip(out_modules, [0 for _ in out_modules])
            _connect_pipeline(cli, out_zipped)
            for mg in tx_pipe.periphery()[0]:
                _connect_pipeline(cli, [mg] + out_zipped[:1])
            tx_pipe.add_modules(out_modules)

            q = QueueOut(port=tx_port, qid=i)
            sink = Sink()
            tx_pipe.tx_rr.connect(q, 0, 0)
            tx_pipe.tx_rr.connect(sink, 1, 0)
            tx_pipes[core] = tx_pipe

            # Setup rate limiting, pin pipelines to cores, connect pipelines
            if ts.mbps is not None:
                bps_per_core = long(1e6 * ts.mbps / num_tx_cores)
                rl_name = \
                    _create_rate_limit_tree(cli, core, 'bit', bps_per_core)
                cli.bess.attach_module(tx_pipe.tx_q.name, rl_name)
            elif ts.pps is not None:
                pps_per_core = long(ts.pps / num_tx_cores)
                rl_name = \
                    _create_rate_limit_tree(cli, core, 'packet', pps_per_core)
                cli.bess.attach_module(tx_pipe.tx_q.name, rl_name)
            else:
                rl_name = None
                cli.bess.attach_module(tx_pipe.tx_q.name, wid=core)
            if rl_name is not None:
                tx_pipe.producers().configure(rl_name)
            tx_pipe.plumb()
            tx_pipe.tc = rl_name
            tx_pipe.add_modules([q, sink])

        # Setup RX pipelines
        rx_qids = dict()
        if num_rx_cores < num_tx_cores:
            for i, core in enumerate(rx_cores):
                rx_qids[core] = [i]

            # round-robin remaining queues across rx_cores
            for i in range(len(tx_cores[num_rx_cores:])):
                core = rx_cores[(num_rx_cores + i) % num_rx_cores]
                rx_qids[core].append(num_rx_cores + i)

        for i, core in enumerate(rx_cores):
            if core not in tx_cores:
                cli.bess.add_worker(wid=core, core=core,
                                    scheduler='experimental')
            rx_pipe = tmode.setup_rx_pipeline(cli, rx_port, ts)

            queues = []
            if core in rx_qids and len(rx_qids[core]) > 1:
                m = Merge()
                front = [m]
                for j, qid in enumerate(rx_qids[core]):
                    q = QueueInc(port=rx_port, qid=qid)
                    queues.append(q)
                    cli.bess.attach_module(q.name, wid=core)
                    q.connect(m, igate=j)
            else:
                q = QueueInc(port=rx_port, qid=i)
                front = [q]
                cli.bess.attach_module(q.name, wid=core)

            measure_name = 'trafficgen_measure_c{}'.format(core)
            front += [
                Measure(name=measure_name, offset=ts.rx_timestamp_offset, jitter_sample_prob=1.0)]
            front_zipped = zip(front, [0 for _ in front])
            _connect_pipeline(cli, front_zipped)
            rx_pipe.add_modules(front)
            ingress = rx_pipe.periphery()[0][0]
            _connect_pipeline(cli, front_zipped[-1:] + [ingress])
            rx_pipe.plumb()

            rx_pipes[core] = rx_pipe

            # TODO: maintain queues in a separate structure
            rx_pipe.add_modules(queues)

        cli.bess.resume_all()

    sess = Session(tx_port, rx_port, ts,
                   mode, tx_pipes, rx_pipes, cli.bess, cli)
    sess.start_monitor()
    cli.add_session(sess)


def _stop(cli, port):
    global available_cores
    sess = cli.remove_session(port)
    sess.stop_monitor()
    cli.remove_session(str(sess.rx_port()))
    reclaimed_cores = sess.spec().tx_cores + sess.spec().rx_cores
    available_cores = list(sorted(available_cores + reclaimed_cores))
    with cli.bess_lock:
        cli.bess.pause_all()
        try:
            workers = set()
            for core, pipe in sess.tx_pipelines().items():
                for m in pipe.modules():
                    cli.bess.destroy_module(m.name)
                workers.add(core)

            for core, pipe in sess.rx_pipelines().items():
                for m in pipe.modules():
                    cli.bess.destroy_module(m.name)
                workers.add(core)

            for worker in workers:
                cli.bess.destroy_worker(worker)

            cli.bess.destroy_port(sess.tx_port())
            if sess.rx_port() != sess.tx_port():
                cli.bess.destroy_port(sess.rx_port())
        finally:
            cli.bess.resume_all()


@cmd('stop PORT...', 'Stop sending packets on a set of ports')
def stop(cli, tx_ports):
    for port in ports:
        _stop(cli, tx_port)
