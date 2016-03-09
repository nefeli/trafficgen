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

import job_pb2
import status_pb2

IP = 'localhost'
PORT = 1800

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pktgen_scheduler")

class Q(object):
    """
    Q is a multi-threaded job scheduler.
    """
    def __init__(self, ip, port, nodes_file, jobs_file):
        self.ip = ip
        self.port = port
        self.sock = None
        self.nodes = {}
        self.jobs = []
        if nodes_file:
            self.nodes = self.load_nodes(nodes_file)
        if jobs_file:
            self.jobs = self.load_jobs(jobs_file)

    def start(self):
        """
        Setup the socket, start all the jobs, and beginning listening
        for statuses.
        """
        logger.info('Starting job scheduler.')
        self.setup_socket()
        self.start_jobs()
        threading.Thread(target=self.listen).start()

    def start_jobs(self):
        """
        Start jobs on each node.
        """
        logger.info('Starting node jobs.')
        for node in set(self.nodes.values()):
            node.next_job()

    def add_job(self, node_id, job):
        """
        Add a job to a specific node.
        """
        if node_id in self.nodes:
            self.jobs.append(job)
            self.nodes[node_id].add_job(job)
            self.nodes[node_id].next_job() # run job if idle
        else:
            logger.error('Cannot add job to node %s as it does not exist.' % node_id)

    def add_node(self, node):
        """
        """
        if node.name not in self.nodes and node.ip not in self.nodes:
            self.nodes[node.name] = self.nodes[node.ip]  = node
        else:
            logger.error('Cannot add node %s as it already exists.' % node.addr())

    def listen(self, backlog=5):
        """
        Listen for status. If one comes in, just spin off a
        thread to handle it.
        """
        self.sock.listen(backlog)
        logger.info('Currently listening on (%s, %s) for any statuses.' % (str(self.ip), str(self.port)))
        while True:
            client_sock, client_addr = self.sock.accept()
            threading.Thread(target=self.handle_client, 
                             args=(client_sock, client_addr)).start()

    def handle_client(self, sock, addr):
        """
        Handle status from client; for now, just see if the
        job successfully finished and move on the next job if
        it exists.
        """
        ip = str(addr[0])
        logger.info('Received status from ip %s.' % ip)

        if ip not in self.nodes:
            logger.error('Ip %s is not one of the nodes' % ip)
            sock.close()
            return
       
        try:
            status = self.read_status(sock)
            if status.type == status_pb2.Status.SUCCESS:
                logger.info('Node %s successfully completed job.' % self.nodes[ip].addr())
                self.nodes[ip].finish_current_job()
                self.nodes[ip].next_job()
            if status.type == status_pb2.Status.FAIL:
                logger.info('Node %s successfully completed job.' % self.nodes[ip].addr())
        except:
            logger.info('Failed to read status from node %s' % self.nodes[ip].addr())
            pass

        sock.close()

    def read_status(self, sock):
        """
        Read the status. The first 4 bytes represent the
        size of the status. The rest is read from the socket
        and then converted from string -> Status using protobuf.
        """
        len_buf = self.read_n_bytes(sock, 4)
        status_len = struct.unpack('>L', len_buf)[0]
        status_buf = self.read_n_bytes(sock, status_len)

        status = status_pb2.Status()
        status.ParseFromString(status_buf)

        return status

    def read_n_bytes(self, sock, n_bytes):
        """
        Simply read n bytes from the sock.
        """
        data = ''
        while n_bytes > 0:
            tmp_buf = sock.recv(n_bytes)
            if not tmp_buf:
                break
            data += tmp_buf
            n_bytes -= len(tmp_buf)
        return data

    def setup_socket(self):
        """
        Setup thte sock on (self.ip, self.port).
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.ip, self.port))
        logger.debug("Successfully setup listening socket.")

    def load_nodes(self, nodes_file):
        """
        Load all the nodes from nodes_file.
        """
        logger.info("Loading nodes file %s." % nodes_file)
        nodes = {}
        node_data = self.load_json(nodes_file)
        
        for node in node_data['nodes']:
            nodes[node['name']] = nodes[node['ip']]  \
                                = Node(node['name'], node['ip'])

        return nodes

    def load_jobs(self, jobs_file):
        """
        Load all the jobs from jobs_file.
        """
        logger.info("Loading jobs file %s." % jobs_file)
        jobs = []
        jobs_data = self.load_json(jobs_file)

        for job in jobs_data['jobs']:
            for node in job['nodes']:
                if node in self.nodes:
                    j = Job(job['priority'], job['data'])
                    self.nodes[node].add_job(j)
                    jobs.append(j)
                else:
                    logger.error("Node %s does not exist." % node)

        return jobs

    def load_json(self, json_file):
        """
        Convert json_file to dictionary.
        """
        with open(json_file, 'r') as json_data:
            return json.load(json_data)

    def stop(self):
        """
        Stop the Q job scheduler.
        """
        if self.sock:
            self.sock.close()

class Node(object):
    """
    Node represents a computer running pkt_server.c
    """

    def __init__(self, name, ip, port):
        self.name = name
        self.ip = ip
        self.port = port
        self.sock = None
        self.pending_jobs = Queue.PriorityQueue()
        self.working_job = None # doesn't need to be queue (just consistency)
        self.completed_jobs = []

    def add_job(self, job):
        """
        Add a job to the pending jobs.
        """
        self.pending_jobs.put((job.priority, job))

    def next_job(self):
        """
        Move on the next job if currently idle.
        """
        # currently a working job, not ready
        if self.working_job:
            return
        
        try:         
            # pop off next job   
            priority, job = self.pending_jobs.get(False)
            # setup socket, send job, and close
            self.setup_socket()
            self.send_job(job)
            self.sock.close()
            # finish job and set working job
            self.pending_jobs.task_done()
            self.working_job = job
            logger.info("Successfully sent job to node %s." % self.addr())
        except Queue.Empty as e:
            logger.info("No pending jobs for node %s." % self.addr())
            pass
        except socket.error as e:
            logger.info("Failed to send job to %s." % self.addr())
            pass

    def send_job(self, job):
        """
        Send the serialized job to node.
        """
        sdata = job.pack() # pack the data
        length = struct.pack('>L', len(sdata)) # pack the length in 4 bytes
        self.sock.sendall(length + sdata) # send it off length + data

    def finish_current_job(self):
        """
        Mark the current job finished
        """
        if self.working_job:
            self.completed_jobs.append(self.working_job)
            self.working_job = None           

    def setup_socket(self):
        """
        Setup sock on (self.ip, self.port).
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.connect((self.ip, self.port)) 
        logger.debug("Successfully setup socket to node %s." % self.addr())

    def addr(self):
        """
        Just return node in (ip, port) format
        """
        return '(%s, %s)' % (str(self.ip), str(self.port))

class Job(object):
    """
    Represents a job to be passed to nodes.
    """
    def __init__(self, priority, data):
        self.priority = priority
        self.job = self.load_job(data)

    def load_job(self, data):
        """
        Load a job from data -> Job type from protobuf.
        """
        j = job_pb2.Job()
        for k, v in data.items():
            if hasattr(j, k):
                setattr(j, k, v)
        return j

    def pack(self):
        """
        Serialize Job to string to be sent to nodes.
        """
        return self.job.SerializeToString()

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

    args = parser.parse_args()

    if args.port:
        q_port = args.port

    if args.nodes:
        q_nodes_file = args.nodes

    if args.jobs:
        q_jobs_file = args.jobs

    q = Q(q_ip, q_port, q_nodes_file, q_jobs_file)
    q.start()

    code.interact(local=dict(globals(), **locals()))

    # this is the equivalent to running 'python ./scheduler/pktgen_scheduler.py -n data/nodes.json -j data/jobs.json'
    # q = Q(IP, PORT)
    # q.add_node(Node('m0', '127.0.0.1'))
    # q.add_job('m0', Job(1, {
    #                             "m": 20,
    #                             "t": 30,
    #                             "w": 5,
    #                             "n": 15,
    #                             "s_min": 200,
    #                             "s_max": 800,
    #                             "r": True,
    #                             "l": True
    #                         }))
    # q.add_job('m0', Job(2, {
    #                             "m": 40,
    #                             "t": 30,
    #                             "w": 5,
    #                             "n": 15,
    #                             "s_min": 500,
    #                             "s_max": 0,
    #                             "r": True,
    #                             "l": False
    #                         }))    
    # start the scheduler
    # q.start()

if __name__ == '__main__':
    main()
