#!/usr/bin/env python3

import argparse
from ruamel.yaml import YAML
import sys

def load_yaml_config(conf_path):
    yaml = YAML(typ='safe')
    with open(conf_path, 'r') as f:
        return yaml.load(f.read())

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Make configs')
    parser.add_argument('src_vni', type=int)
    parser.add_argument('flow_rate', type=int)
    parser.add_argument('flow_dur', type=int)
    parser.add_argument('flow_pps', type=int)
    parser.add_argument('pkt_size', type=int)
    parser.add_argument('--dst-vni', type=int)
    args = parser.parse_args()

    def vni2prefix(vni):
        if vni & 512:
            return 13
        elif vni & 256:
            return 12
        elif vni < 256:
            return 11
        else:
            assert False

    def vni2pipe(vni):
        return vni & ~768

    dsts = {11: 12, 12: 13, 13: 11}
    src_prefix = vni2prefix(args.src_vni)
    dst_prefix = vni2prefix(args.dst_vni) if args.dst_vni is not None else dsts[src_prefix]

    src_ports = {
        11: (8000, 9000),
        12: (8000, 9000),
        13: (8000, 9000)}
    dst_ports = {
        11: (3478, 3481),
        12: (3478, 3481),
        13: (3478, 3481)}

    pipe_id = vni2pipe(args.src_vni)

    src_net_min = '{}.0.{}.2'.format(src_prefix, pipe_id)
    src_net_max = '{}.0.{}.255'.format(src_prefix, pipe_id)

    dst_net_min = '{}.0.{}.2'.format(dst_prefix, pipe_id)
    dst_net_max = '{}.0.{}.255'.format(dst_prefix, pipe_id)

    rate_conf = {
        'pkt_size': args.pkt_size,
        'flow_rate': args.flow_rate,
        'flow_duration': args.flow_dur,
        'pps_per_flow': args.flow_pps}

    id_conf = {
        'vni': args.src_vni,
        'weight': 1}

    mac_conf = {
        'dst_macs': ['00:16:3d:22:33:58'],
        'dummy_mac': '02:00:00:00:00:01'}

    ip_conf = {
        'tun_src_ip': '192.168.1.1',
        'tun_dst_ip': '192.168.1.3',
        'min_src_ip': src_net_min,
        'max_src_ip': src_net_max,
        'min_dst_ip': dst_net_min,
        'max_dst_ip': dst_net_max}

    port_conf = {
        'min_src_port': src_ports[src_prefix][0],
        'max_src_port': src_ports[src_prefix][1],
        'min_dst_port': dst_ports[dst_prefix][0],
        'max_dst_port': dst_ports[dst_prefix][1]}

    misc_conf = {
        'name': '{}to{}'.format(src_prefix, dst_prefix),
        'proto': 17,
        'quick_rampup': True}

    yaml = YAML(typ='safe')
    yaml.default_flow_style = False

    sys.stdout.write('# Rate Options\n')
    yaml.dump(rate_conf, sys.stdout)
    sys.stdout.write('\n')

    sys.stdout.write('# Pipeline Options\n')
    yaml.dump(id_conf, sys.stdout)
    sys.stdout.write('\n')

    sys.stdout.write('# Addresses\n')
    yaml.dump(mac_conf, sys.stdout)
    yaml.dump(ip_conf, sys.stdout)
    sys.stdout.write('\n')

    sys.stdout.write('# Ports\n')
    yaml.dump(port_conf, sys.stdout)
    sys.stdout.write('\n')

    sys.stdout.write('# Misc. Options\n')
    yaml.dump(misc_conf, sys.stdout)
