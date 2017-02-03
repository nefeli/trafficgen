import time
from control import *
from pprint import pprint
def start_traffic(socket, duration, tx_mbps, size):
    job = create_minimal_job(tx_mbps, duration * 1000, size, size)
    job.latency = True
    request = create_request(job)
    send_request(socket, request)
    resp = recv_response(socket)
    pprint(str(resp))
    time.sleep(duration + 0.5)
    stop_job = create_print_job()
    stop_job.stop = True
    print stop_job.stop
    send_request(socket, create_request(stop_job))
    resp = recv_response(socket)
    pprint(str(resp))
    return resp

def main():
    server = "127.0.0.1"
    port = 5000
    socket = connect(server, port)
    start_traffic(socket, 10, 10000, 60)
    socket.close()

if __name__ == '__main__':
    main()
