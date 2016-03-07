import time
from control import *

import job_pb2
import status_pb2

def start_traffic(q, server_id, tx_mbps, dur_sec):
    try:
        dur_msec = int(dur_sec * 1000)
        q.add_job(server_id, Job(1, {
            "tx_rate": tx_mbps,
            "duration": dur_msec,
            "warmup": 0,
            "num_flows": 1,
            "size_min": 64,
            "size_max": 64,
            "life_min": dur_msec,
            "life_max": dur_msec,
            "port_min": 1024,
            "port_max": 2048}))
        time.sleep(dur_sec)
    except:
        q.add_job(server_id, Job(0, {"stop": True}))

def main():
    q = Q("127.0.0.1", 1800, None, None)
    q.start()

    server_ip = "127.0.0.1"
    server_port = 5000
    server_id = "%s:%d" % (server_ip, server_port)
    q.add_node(Node(server_id, server_ip, server_port))
    print("Starting traffic. Press ctrl + c to stop")
    # Generate 1 10gbps flow of 64B packets for 10 seconds
    start_traffic(q, server_id, 10000, 10)
    q.stop()

if __name__ == '__main__':
    main()
