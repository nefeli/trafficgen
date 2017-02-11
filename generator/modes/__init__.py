import commands as bess_commands
from module import *

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

def create_rate_limit_tree(cli, wid, resource, limit):
    rr_name = 'rr_w%d' % (wid,)
    rl_name = 'rl_pps_w%d' % (wid,)
    leaf_name = 'bit_leaf_w%d' % (wid,)
    cli.bess.add_tc(rr_name, wid=wid, policy='round_robin', priority=0)
    cli.bess.add_tc(rl_name, parent=rr_name, policy='rate_limit',
                    resource=resource, limit={resource: limit})
    cli.bess.add_tc(leaf_name, policy='leaf', parent=rl_name)
    return (rr_name, rl_name, leaf_name)

from udp import UdpMode
from flowgen import FlowGenMode
from http import HttpMode
