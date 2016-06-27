import time
from control import Request, Job, Q, Node
from pprint import pprint


def start_traffic(q, server_id, tx_mbps, dur_sec):
    macs = ["eth_ring0",
            "eth_ring1"
            #"68:05:ca:33:ff:f8",
            #"68:05:ca:27:9a:5a",
            #"68:05:ca:27:9a:5b",
            #"68:05:ca:27:9a:5f",
            #"68:05:ca:27:99:47",
            #"68:05:ca:27:9a:47",
            ]
    dur_msec = int(dur_sec * 1000)
    q.add_job(server_id,
              Request(1,
                      [Job({"port": mac,
                            "src_mac": "01:02:03:04:05:01",
                            "dst_mac": "01:02:03:04:05:11",
                            "tx_rate": tx_mbps,
                            "duration": dur_msec,
                            "warmup": 2000,
                            "num_flows": 100000,
                            "size_min": 1514,
                            "size_max": 1514,
                            "life_min": dur_msec,
                            "life_max": dur_msec,
                            "latency": True,
                            "randomize": False,
                            "port_min": 0,
                            "port_max": 65535})
                       for mac in macs]))
    time.sleep(dur_sec + 0.5)
    q.add_job(server_id,
              Request(1, [Job({"print": True})]))
    time.sleep(0.5)
    try:
        return {mac: q.results[server_id][mac] for mac in macs}
    except:
        print(q.results)
        return None

def main():
    q = Q("127.0.0.1", 1800, None, None)
    q.start()

    server_ip = "127.0.0.1"
    server_port = 5000
    server_id = "%s:%d" % (server_ip, server_port)
    q.add_node(Node(server_id, server_ip, server_port))
    print("Starting traffic. Press ctrl + c to stop")
    # Generate 1 10gbps flow of 64B packets for 10 seconds
    pprint(start_traffic(q, server_id, 10000, 5))
    q.stop()

if __name__ == '__main__':
    main()
