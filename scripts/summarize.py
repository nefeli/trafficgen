#!/usr/bin/env python
import argparse
import collections
import json
import numpy as np
import os
import sys

fields = ['in_mbps', 'in_mpps', 'rtt_avg', 'rtt_med', 'rtt_99', 'out_mbps', 'out_mpps']
Measurement = collections.namedtuple('Measurement', fields)

if __name__ == '__main__':
    results = dict()
    csv = sys.argv[1] if len(sys.argv) > 1 else '/tmp/bench.csv'
    f = open(csv)
    for line in f:
        if line[0] == '#':
            continue
        try:
            line = line.strip().split(',')
            port = line[1]
            if port not in results:
                results[port] = list()
            in_mbps = float(line[2])
            in_mpps = float(line[3])
            rtt_avg = float(line[5])
            rtt_med = float(line[6])
            rtt_99 = float(line[6])
            out_mbps = float(line[11])
            out_mpps = float(line[12])
            m = Measurement(in_mbps, in_mpps, rtt_avg, rtt_med,
                            rtt_99, out_mbps, out_mpps)
            results[port].append(m)
        except:
            continue
    f.close()

    def summarize_measurements(measurements, summary_func=np.mean):
        rtt_avg = []
        rtt_med = []
        rtt_99 = []
        in_mbps = []
        in_mpps = []
        out_mbps = []
        out_mpps = []
        for m in measurements:
            rtt_avg.append(m.rtt_avg)
            rtt_med.append(m.rtt_med)
            rtt_99.append(m.rtt_99)
            in_mbps.append(m.in_mbps)
            in_mpps.append(m.in_mpps)
            out_mbps.append(m.out_mbps)
            out_mpps.append(m.out_mpps)

        # It's a slight abuse to call this summary a "Measurement"...
        return Measurement(summary_func(in_mbps), summary_func(in_mpps), 
                           summary_func(rtt_avg), summary_func(rtt_med),
                           summary_func(rtt_99), summary_func(out_mbps), 
                           summary_func(out_mpps))

    def do_print(port, summary):
        xput = '{:.3f} Mpps / {:.3f} Mbps'
        keys = ['Throughput in', 'Throughput out',
                'Median RTT', '99th-percentile RTT']
        vals = [
            xput.format(summary.in_mpps, summary.in_mbps),
            xput.format(summary.out_mpps, summary.out_mbps),
            '{:.3f} usec'.format(summary.rtt_med),
            '{:.3f} usec'.format(summary.rtt_99)
        ]
        data = dict(zip(keys, vals))
        col_len = max([len(x) for x in data.keys()])
        fmt = '{:<' + str(col_len) + '}\t{}'
        print(port)
        print('-' * len(port))
        for k in keys:
            print(fmt.format('{}:'.format(k), data[k]))


    summarized_results = {}
    for port, measurements in results.items():
        summarized_results[port] = summarize_measurements(measurements)

    # TODO: cmd line flag for dumping json?
    json_file = os.path.splitext(csv)[0] + '_summary.json'
    with open(json_file, 'w') as f:
        json.dump(summarized_results, f)

    n = len(results.keys())
    total = None
    for port, summary in summarized_results.items():
        if port == 'Total':
            total = summary
            continue
        n -= 1
        do_print('Port: {}'.format(port), summary)
        if n > 0:
            print('')

    if total is not None:
        do_print('Total', total)
