import os
import sys
import json
import code
import time
import subprocess
import smtplib
from pprint import pprint

from control import *
import job_pb2
import status_pb2

IP = 'localhost'
PORT = 1800
HOST="c51"

adaptive_check = lambda x: x if x >= 0 else -1

UL_PKT_SIZE = 164
DL_PKT_SIZE = 64
UL_MPPS = float(sys.argv[1])
DL_MPPS = float(sys.argv[2])
UL_SPEED = adaptive_check(int(UL_MPPS * UL_PKT_SIZE * 8))
DL_SPEED = adaptive_check(int(DL_MPPS * DL_PKT_SIZE * 8))

def txt(number):
    fromaddr = "mwalls67@gmail.com"
    toaddr  = "%s@txt.att.net" % number
    msg = "\r\n".join([
        "From: mwalls67@gmail.com",
        "To: %s" % toaddr,
        "Subject: ",
        "",
        "|%s| eval is done :)" % time.strftime("%d/%m/%Y @ %H:%M")
    ])
    username = "mwalls67"
    password = "wiqkyygufbchijxp"
    server = smtplib.SMTP('smtp.gmail.com:587')
    server.ehlo()
    server.starttls()
    server.login(username,password)
    server.sendmail(fromaddr, toaddr, msg)
    server.quit()

def ssh(cmd):
    x = subprocess.Popen(["ssh", "-l", "melvin", HOST, cmd],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
    """
    o_lines = x.stdout.readlines()
    for line in o_lines:
        sys.stdout.write("[SSH STDOUT] %s%s" % (line, "\n" \
                if line[-1] != "\n" else ""))
    e_lines = x.stderr.readlines()
    for line in e_lines:
        sys.stdout.write("[SSH STDERR]: %s%s" % (line, "\n" \
                if line[-1] != "\n" else ""))
    return o_lines, e_lines
    """

def mem_from_free():
    out,err = ssh("free -k")
    if len(out) >= 2:
        keys = out[0].split()
        mem = out[1].split()
        return dict(zip(keys, map(int, mem[1:])))

def mem_from_ps(p):
    out,err = ssh("bash -c \"ps -e -o pid,rss,comm= | grep %s\"" % (p,))
    if len(out) >= 1:
        line = out[0].split()
        return int(float(line[1]))

def run(q, mac, tx_r, dur, warm, n_flows, sz, life, gtpu=False):
    s = ("127.0.0.1", 5000)
    ip_str = "%s:%d" % (s[0], s[1])
    q.add_node(Node(ip_str, s[0], s[1]))

    #q.results[ip_str] = {}
    macs = [mac]
    try:
        jobs = [Job({
            "tx_rate": tx_r,
            "duration": int(dur * 1000),
            "warmup": int(warm * 1000),
            "port": mac,
            "num_flows": n_flows,
            "size_min": sz[0],
            "size_max": sz[1],
            "life_min": int(life[0] * 1000),
            "life_max": int(life[1] * 1000),
            "latency": True, "online": True, "gtpu": gtpu})
            for mac in macs]
        q.add_job(ip_str, Request(1, jobs))
        """
        time.sleep(dur + 2)
        q.results[ip_str] = {}
        q.add_job(ip_str, Request(1, [Job({"print": True, "stop": True})]))
        time.sleep(5)
        pprint(q.results[ip_str][mac])
        return q.results[ip_str][mac]
        """
    except:
        q.add_job(ip_str, Request(1, (Job({"stop": True}),)))

def do_exp(q, exp=""):
    s = ("127.0.0.1", 5000)
    ip_str = "%s:%d" % (s[0], s[1])
    q.add_node(Node(ip_str, s[0], s[1]))

    print("Running experiment: %s" % (exp,))

    data_file = "data-%s.json" % (exp,)
    data = {}
    try:
        data = eval(open(data_file).read())
    except:
        data = {}
        pass

    evals = []
    probes = range(1,33)
    flows = (1000, 10000, 100000)
    sizes = (64,)# 768)
    percs = (1, 5, 10, 25, 50, 75, 100)
    dur_sec = 30
    params = ('k', 'p', 'f', 's')
    for p in probes:
        for k in percs:
            for f in flows:
                for s in sizes:
                    if k < 100:
                        continue
                    evals.append((k, p, f, s))

    print("[START EXP: %s]" % (exp,))
    print("Runtime: %d minutes" % (len(evals) * (dur_sec + 5)/float(60),))
    for e in evals:
        k = int(e[0])
        num_probes = e[1]
        num_flows = e[2]
        pkt_sz = e[3]
        key = tuple(zip(params, e))
        #key = "1p-%dk-%df-%dB" % (e[0], e[1], e[2])
        r = (-1, dur_sec, 5, num_flows, (pkt_sz, pkt_sz), (1, 1))

        if key in data:
            print("Skipping %s" % (dict(key),))
            continue

        print("[START %s]" % (dict(key),))
        print("[BOOT BESS/profiler]")
        cmd = "cd bess && sudo ./boot.sh %d %d %d %d" % (num_probes, \
                num_probes, k, dur_sec)
        ssh(cmd)

        time.sleep(5)
        print("Starting traffic")
        data[key] = run(q, r[0], r[1], r[2], r[3], r[4], r[5])

        try:
            out, err = ssh('cat /home/melvin/bess/profiler_stats.txt')
            if len(out) > 0:
                l = out[0].split()
                data[key]['profiler_pkts'] = int(l[0])
                data[key]['profiler_kbytes'] = int(l[1]) / float(1024)
        except:
            print("Failed to fetch profiler performance")

        try:
            out, err = ssh('cat /home/melvin/bess/bess_stats.txt')
            if len(out) > 0:
                l = out[0].split()
                data[key]['bess_enq_success_objs'] = int(l[0])
                data[key]['bess_enq_fail_objs'] = int(l[1])
                data[key]['bess_deq_success_objs'] = int(l[2])
                data[key]['bess_deq_fail_objs'] = int(l[3])
        except:
            print("Failed to fetch profiler performance")

        print("[STATS]")
        pprint(data[key])
        print("[END %s]" % (dict(key),))

        print("Writing intermediate stats to %s" % (data_file,))
        f = open(data_file, "w+")
        pprint(data, stream=f)
        f.close()

    print("[END EXP: %s]" % (exp,))

def start_traffic(q, ip, port, tx_mbps, dur_sec):
    server_id = "%s:%d" % (ip, port)
    q.add_node(Node(server_id, ip, port))
    try:
        dur_msec = int(dur_sec * 1000)
        q.add_job(server_id, Job(1, {
            "tx_rate": tx_mbps,
            "duration": dur_msec,
            "warmup": 0,
            "num_flows": 1,
            "size_min": 164,
            "size_max": 164,
            "life_min": dur_msec,
            "life_max": dur_msec,
            "port_min": 2152,
            "port_max": 2152}))
        time.sleep(dur_sec)
    except:
        q.add_job(server_id, Job(0, {"stop": True}))

def doit(q, u_sz=UL_PKT_SIZE, d_sz=DL_PKT_SIZE, num_ue=None, active_ue=None, window=None, inserts=None, mods=None,
    dels=None, update_freq=None, update_batch=None, eval_mode=None,
    data_core=None, ctrl_core=None, ul_port=None, dl_port=None,
    dumb_pipe="false", packet_loss=False, u_mpps=UL_MPPS, d_mpps=DL_MPPS):
    s = ("127.0.0.1", 5000)
    ip_str = "%s:%d" % (s[0], s[1])
    uport = "00:1e:67:d1:89:40"
    dport = "00:1e:67:d1:89:41"
    args = "%d %d %d %d %d %d %d %d %d %d %d %s %s %s"
    args = args % (num_ue, active_ue, window, inserts, mods, dels, update_freq,
            update_batch, eval_mode, data_core, ctrl_core, ul_port, dl_port,
            dumb_pipe)
    ssh("cd /opt/pepc/datapath && nohup ./do_eval.py %s &" % (args,))
    time.sleep(25)
    ul_speed = adaptive_check(int(u_mpps * UL_PKT_SIZE * 8))
    dl_speed = adaptive_check(int(d_mpps * DL_PKT_SIZE * 8))
    q.results[ip_str] = {}
    try:
        if num_ue >= 10000000:
            run(q, uport, ul_speed, 30, 20, 1, (u_sz,u_sz), (30,30), True)
            run(q, dport, dl_speed, 30, 20, 1, (d_sz,d_sz), (30,30), False)
            time.sleep(35)
        else:
            run(q, uport, ul_speed, 15, 5, 1, (u_sz,u_sz), (15,15), True)
            run(q, dport, dl_speed, 15, 5, 1, (d_sz,d_sz), (15,15), False)
            time.sleep(15)
        q.add_job(ip_str, Request(1, [Job({"print": True, "stop": True})]))
    except:
        q.add_job(ip_str, Request(1, (Job({"stop": True}),)))
    time.sleep(3)
    pprint(q.results[ip_str])
    u_rx_mpps = q.results[ip_str][uport.upper()]['rx_mpps_mean']
    d_rx_mpps = q.results[ip_str][dport.upper()]['rx_mpps_mean']
    u_tx_mpps = q.results[ip_str][uport.upper()]['tx_mpps_mean']
    d_tx_mpps = q.results[ip_str][dport.upper()]['tx_mpps_mean']
    u_rtt = dict([(k, q.results[ip_str][uport.upper()][k]) for k in ['rtt_0',
        'rtt_25', 'rtt_50', 'rtt_75', 'rtt_100']])
    d_rtt = dict([(k, q.results[ip_str][dport.upper()][k]) for k in ['rtt_0',
        'rtt_25', 'rtt_50', 'rtt_75', 'rtt_100']])
    if not packet_loss:
        return (
            (u_rx_mpps + d_rx_mpps) * 1000000,
            u_rtt,
            d_rtt,
        )
    return (
        ((u_tx_mpps + d_tx_mpps) - (u_rx_mpps + d_rx_mpps)) * 1000000,
        u_rtt,
        d_rtt,
    )

def append_results(csv, ret, col0):
    f = open(csv, "a+")
    line = "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n" % (
        col0,
        ret[0],
        ret[1]['rtt_0'],
        ret[1]['rtt_25'],
        ret[1]['rtt_50'],
        ret[1]['rtt_75'],
        ret[1]['rtt_100'],
        ret[2]['rtt_0'],
        ret[2]['rtt_25'],
        ret[2]['rtt_50'],
        ret[2]['rtt_75'],
        ret[2]['rtt_100'],
    )
    f.write(line)
    f.close()
    return line

def run_ues(q, ctrl_core, data_core, ul_port, dl_port):
    ue_counts = [100000, 250000, 500000, 750000, 1000000,]#10000000]
    #ue_counts = [1000000,]
    ctrl_windows = [10000,4800]
    #ctrl_windows = [4800,]
    dels=0
    update_freq=32
    update_batch=32

    experiments = [] # (num_ue, inserts, mods)
    for num_ue in ue_counts:
        for window in ctrl_windows:
            experiments.append((num_ue, window, window, 0))

    print("device count")
    print("============")
    print("running %d experiments" % (len(experiments),))
    for ex in experiments:
        num_ue = ex[0]
        window = ex[1]
        inserts = ex[2]
        mods = ex[3]
        ret = doit(q, UL_PKT_SIZE, DL_PKT_SIZE, *(num_ue, num_ue, window, inserts, mods, dels,
            update_freq, update_batch, 0, data_core, ctrl_core, ul_port,
            dl_port), packet_loss=False, u_mpps=7/4.0, d_mpps=21/4.0)
        csv = 'data/ues-%d-%.3f:%.3f.csv' % (window, UL_MPPS, DL_MPPS)
        line = append_results(csv, ret, num_ue)
        print(line.strip())

def run_inserts_mods(q, ctrl_core, data_core, ul_port, dl_port):
    #ue_counts = [250000, 1000000, 10000000]
    ue_counts = [1000000,]
    #ctrl_windows = [0, 10000, 50000, 100000, 150000]
    ctrl_windows = [10000,4800,]
    dels=0
    update_freq=32
    update_batch=32

    results = {
        'mods': [],
        'inserts': [],
    }
    experiments = [] # (num_ue, inserts, mods)
    for num_ue in ue_counts:
        for window in ctrl_windows:
            experiments.append((num_ue, window, 0, window))
            if window == 0: continue
            experiments.append((num_ue, window, window, 0))

    print("inserts/mods")
    print("============")
    print("running %d experiments" % (len(experiments),))
    for ex in experiments:
        num_ue = ex[0]
        window = ex[1]
        inserts = ex[2]
        mods = ex[3]
        ret = doit(q, UL_PKT_SIZE, DL_PKT_SIZE, *(num_ue, num_ue, window, inserts, mods, dels,
            update_freq, update_batch, 0, data_core, ctrl_core, ul_port,
            dl_port), u_mpps=7/4.0, d_mpps=21/4.0)
        if num_ue not in results:
            results[num_ue] = {'mods': [], 'inserts': []}
        if window == 0:
            csv = 'data/insert-%d.csv' % (num_ue,)
            line = append_results(csv, ret, window)
            print('inserts', line.strip())
            csv = 'data/modify-%d.csv' % (num_ue,)
            line = append_results(csv, ret, window)
            print('mods', line.strip())
        elif inserts == 0 and mods != 0:
            csv = 'data/modify-%d.csv' % (num_ue,)
            line = append_results(csv, ret, window)
            print('mods', line.strip())
        elif mods == 0 and inserts != 0:
            csv = 'data/insert-%d.csv' % (num_ue,)
            line = append_results(csv, ret, window)
            print('inserts', line.strip())

def run_update_period(q, ctrl_core, data_core, ul_port, dl_port):
    ue_counts = [250000, 1000000, 10000000]
    window = 150000
    update_freqs = [1, 16, 32, 64, 128, 256]
    inserts = 150000
    mods = 0
    dels = 0
    update_batch = 32

    experiments = [] # (num_ue, inserts, mods)
    for num_ue in ue_counts:
        for update_freq in update_freqs:
            experiments.append((num_ue, update_freq))

    print("merge period")
    print("============")
    print("running %d experiments" % (len(experiments),))
    for ex in experiments:
        num_ue = ex[0]
        update_freq = ex[1]
        ret = doit(q, UL_PKT_SIZE, DL_PKT_SIZE, *(num_ue, num_ue, window, inserts, mods, dels, update_freq,
                update_batch, 1, data_core, ctrl_core, ul_port, dl_port), u_mpps=7/4.0, d_mpps=21/4.0)
        csv = "data/merge-period-%d.csv" % (num_ue,)
        line = append_results(csv, ret, update_freq)
        print(line.strip())

def run_caching(q, data_core, ctrl_core, ul_port, dl_port, churn="low"):
    ue_counts = [10000000]
    active_counts = [1000, 10000, 100000, 250000, 500000, 1000000, 5000000]
    #active_counts = [100000,]
    maxes = {
        1000: 7.103903,
        10000: 6.571439,
        100000: 5.599876,
        250000: 5.121655,
        500000: 4.237195,
        1000000: 3.787825,
        5000000: 3.339794
    }
    #active_counts = [1000,]
    update_freq=32
    update_batch=32
    window=lambda x: int(x/10.0)
    mods=0

    if churn == "medium":
        window=lambda x: int(x/2.0)
    elif churn == "high":
        window=lambda x: x
    elif churn == None:
        window=lambda x: 0

    experiments = []
    for num_ue in ue_counts:
        for active in active_counts:
            experiments.append((num_ue, active))

    print("caching - %s churn" % (churn,))
    print("============")
    print("running %d experiments" % (len(experiments),))
    for ex in experiments:
        num_ue = ex[0]
        active_ue = ex[1]
        w = window(active_ue)
        u_mpps = UL_MPPS#maxes[active_ue]/4.0
        d_mpps = DL_MPPS#3*maxes[active_ue]/4.0
        ret = doit(q, UL_PKT_SIZE, DL_PKT_SIZE, *(num_ue, active_ue, w, int(w/2), mods, int(w/2),
            update_freq, update_batch, 0, data_core, ctrl_core, ul_port,
            dl_port, 'true' if churn is None else 'false'), u_mpps=u_mpps,
            d_mpps=d_mpps)
        csv = 'data/caching-%s.csv' % (str(churn),)
        line = append_results(csv, ret, active_ue)
        print(line.strip())

def main():
    q = Q(IP, PORT, None, None)
    q.start()
    try:
        print(UL_SPEED, DL_SPEED)
        #run_inserts_mods(q, 1, 2, "02:00.0", "02:00.1")
        run_ues(q, 1, 2, "02:00.0", "02:00.1")
        #run_update_period(q, 1, 2, "02:00.0", "02:00.1")
        #run_caching(q, 1, 2, "02:00.0", "02:00.1", "low")
        #run_caching(q, 1, 2, "02:00.0", "02:00.1", "medium")
        #run_caching(q, 1, 2, "02:00.0", "02:00.1", "high")
        #run_caching(q, 1, 2, "02:00.0", "02:00.1", None) # IoT dumb pipe mode
    finally:
        #txt("5706405618")
        #txt("6314136572")
        print('all done :)')
        q.stop()
    code.interact(local=dict(globals(), **locals()))
    q.stop()

if __name__ == '__main__':
    main()
