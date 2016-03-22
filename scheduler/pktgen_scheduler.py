# -*- coding: utf-8 -*-

"""
pktgen_scheduler.py
---------
pktgen_scheduler talks with pktgen_servers, schedules
jobs and listens for statuses.
"""

import sys
import json
import code
import Queue
import struct
import socket
import logging
import argparse
import threading
import time
import math
from control import *

import job_pb2
import status_pb2

IP = 'localhost'
PORT = 1800

def increase_smoothly(q, server, start_rate, stop_rate, steps, duration, margin, end):
    diff = float(stop_rate - start_rate)
    step_size = math.ceil(diff/float(steps))
    duration_per_step = int(math.ceil(duration / float(steps)))
    runduration = int(math.ceil(duration_per_step + margin))
    for rate in xrange(int(start_rate), int(stop_rate) + 1, int(step_size)):
        q.add_job(server, Job(1, {\
            "tx_rate": rate,\
            "duration": runduration * 1000,\
            "warmup": 0,\
            "num_flows": 300,\
            "size_min": 768,\
            "size_max": 768,\
            "life_min": 1,\
            "life_max": 120,\
            "online": True\
            }))
        time.sleep(duration_per_step)
    q.add_job(server, Job(1, {\
        "tx_rate": int(stop_rate),\
        "duration": end * 1000,\
        "warmup": 0,\
        "num_flows": 300,\
        "size_min": 768,\
        "size_max": 768,\
        "life_min": 1,\
        "life_max": 120,\
        "online": True\
        }))

def decrease_smoothly(q, server, start_rate, stop_rate, steps, duration, margin, end):
    diff = float(start_rate - stop_rate)
    step_size = math.ceil(diff/float(steps))
    duration_per_step = int(math.ceil(duration / float(steps)))
    runduration = int(math.ceil(duration_per_step + margin))
    for rate in xrange(int(stop_rate), int(start_rate), -1 * int(step_size)):
        q.add_job(server, Job(1, {\
            "tx_rate": rate,\
            "duration": runduration * 1000,\
            "warmup": 0,\
            "num_flows": 300,\
            "size_min": 768,\
            "size_max": 768,\
            "life_min": 1,\
            "life_max": 120,\
            "online": True\
            }))
        time.sleep(duration_per_step)
    q.add_job(server, Job(1, {\
        "tx_rate": int(stop_rate),\
        "duration": end * 1000,\
        "warmup": 0,\
        "num_flows": 300,\
        "size_min": 768,\
        "size_max": 768,\
        "life_min": 1,\
        "life_max": 120,\
        "online": True\
        }))

def kill_traffic(q, server):
    q.add_job(server, Job(0, {"stop": True}))

def run_demo_job(q, server, rate):
    duration = 3600 * 1000 # If nothing happens in an hour then we should just 
                           # give up.
    q.add_job(server, Job(1, {\
            "tx_rate": rate, \
            "duration": duration, \
            "warmup": 0,\
            "num_flows": 300,\
            "size_min": 512,\
            "size_max": 768,\
            "life_min": 1,\
            "life_max": 10,\
            "online": True
            }))

def sip_traffic(q, server, rate):
    duration = 3600 * 1000 # If nothing happens in an hour then we should just 
                           # give up.
    q.add_job(server, Job(1, {\
            "tx_rate": rate, \
            "duration": duration, \
            "warmup": 0,\
            "num_flows": 300,\
            "size_min": 512,\
            "size_max": 768,\
            "life_min": 1,\
            "life_max": 10,\
            "port_min": 5060,\
            "port_max": 5061, \
            "online": True
            }))

def run_stress(q):
    server = "s"
    q.add_node(Node(server, "127.0.0.1", 7001))
    while True:
        increase_smoothly(q, server, 20.0, 800.0, 30, 120, 2, 120)
        time.sleep(100)
        decrease_smoothly(q, server, 800.0, 20.0, 30, 120, 2, 120)
        time.sleep(100)
        time.sleep(120)

        increase_smoothly(q, server, 20.0, 800.0, 30, 60, 2, 200)
        time.sleep(185)
        decrease_smoothly(q, server, 800.0, 20.0, 30, 60, 300, 200)
        time.sleep(100)
        time.sleep(120)

        increase_smoothly(q, server, 20.0, 800.0, 5, 15, 2, 30)
        time.sleep(30)
        decrease_smoothly(q, server, 800.0, 20.0, 5, 15, 2, 79)
        time.sleep(60)
        time.sleep(150)

def run_demo(q):
    baseline = 500
    spike = 10000
    mid = 2000
    ports = 1
    server = "s"
    q.add_node(Node(server, "127.0.0.1", 7001))
    while True:
        print "Hello welcome to the E2 demo."
        print "Running baseline traffic"
        run_demo_job(q, server, baseline/ports)
        print "Hit enter to spike"
        raw_input()
        print "Now rapidly spiking traffic"
        run_demo_job(q, server, spike/ports)
        print "Hit enter to decrease midway"
        raw_input()
        print "OK! Whatever was going on is becoming less of a problem now"
        run_demo_job(q, server, mid/ports)
        print "Hit enter to go back to baseline"
        raw_input()
        print "Finally things are entirely dying off"
        run_demo_job(q, server, baseline/ports)
        print "Now let us do that again, but focus on one server"
        print "Hit enter to spike"
        raw_input()
        print "Now rapidly spiking traffic"
        run_demo_job(q, server, spike/ports)
        print "Hit enter to decrease midway"
        raw_input()
        print "OK! Whatever was going on is becoming less of a problem now"
        run_demo_job(q, server, mid/ports)
        print "Hit enter to go back to baseline"
        raw_input()
        print "Finally things are entirely dying off"
        run_demo_job(q, server, baseline/ports)
        print "Hit enter to end demo"
        raw_input()
        print "Thank you"

def run_demo_auto(q):
    baseline = 500
    spike = 10000
    mid = 2000
    ports = 1
    server = "s"
    q.add_node(Node(server, "127.0.0.1", 7001))
    while True:
        print "Hello welcome to the E2 demo."
        print "Running baseline traffic"
        run_demo_job(q, server, baseline/ports)
        print "Hit enter to spike"
        time.sleep(30)
        print "Now rapidly spiking traffic"
        run_demo_job(q, server, spike/ports)
        print "Hit enter to decrease midway"
        time.sleep(30)
        print "OK! Whatever was going on is becoming less of a problem now"
        run_demo_job(q, server, mid/ports)
        print "Hit enter to go back to baseline"
        time.sleep(30)
        print "Finally things are entirely dying off"
        run_demo_job(q, server, baseline/ports)
        print "Now let us do that again, but focus on one server"
        print "Hit enter to spike"
        time.sleep(30)
        print "Now rapidly spiking traffic"
        run_demo_job(q, server, spike/ports)
        print "Hit enter to decrease midway"
        time.sleep(30)
        print "OK! Whatever was going on is becoming less of a problem now"
        run_demo_job(q, server, mid/ports)
        print "Hit enter to go back to baseline"
        time.sleep(30)
        print "Finally things are entirely dying off"
        run_demo_job(q, server, baseline/ports)
        print "Hit enter to end demo"
        time.sleep(30)
        print "Thank you"

def demo_console(q):
    tenant0_pgen = "t0p"
    q.add_node(Node(tenant0_pgen, "127.0.0.1", 7001))
    print "adding t0p"
    tenant1_pgen = "t1p"
    q.add_node(Node(tenant1_pgen, "127.0.0.1", 7002))
    print "Adding t1p"
    code.interact(local=dict(globals(), **locals()))

def main():
    q_ip = IP
    q_port = PORT
    q_nodes_file = q_jobs_file = None

    parser = argparse.ArgumentParser(
        description="pktgen_scheduler schedules jobs for pktgen_servers")

    parser.add_argument('-p', '--port', type=int, help='the port pktgen_scheduler will listen on')
    parser.add_argument('-n', '--nodes', type=str, help='nodes json file to load')
    parser.add_argument('-j', '--jobs', type=str, help='jobs json file to load')
    parser.add_argument('-i', '--interactive', action="store_true", help='interactive mode')
    parser.add_argument('-d', '--demo', action="store_true", help='demo mode')

    args = parser.parse_args()

    if args.port:
        q_port = args.port

    if args.nodes:
        q_nodes_file = args.nodes

    if args.jobs:
        q_jobs_file = args.jobs

    q = Q(q_ip, q_port, q_nodes_file, q_jobs_file)
    q.start()
    if args.demo:
        demo_console(q)
    else:

        code.interact(local=dict(globals(), **locals()))

    q.stop()


if __name__ == '__main__':
    main()
