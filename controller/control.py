from job_pb2 import *
from status_pb2 import *
import socket
import struct
BCAST_MAC = "00:00:00:00:00:00"
def create_minimal_job(tx_rate, duration, size_min, size_max):
    assert(duration != 0) # If 0 then nothing will really happen
    job = Job()
    job.tx_rate = tx_rate
    job.num_flows = 1
    job.size_min = size_min
    job.size_max = size_max
    job.port = BCAST_MAC
    job.duration = duration
    return job

def create_port_job(port, tx_rate, duration, size_min, size_max):
    assert(duration != 0)
    job = create_minimal_job(tx_rate, duration, size_min, size_max)
    job.port = port
    return job

def create_print_job():
    job = Job()
    setattr(job, "print", True)
    job.port = BCAST_MAC
    return job

def create_request(jobs):
    if not isinstance(jobs, list):
        jobs = [jobs]
    request = Request()
    request.jobs.extend(jobs)
    return request

def connect(pktgen_ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((pktgen_ip, port))
    return sock

def send_request(socket, request):
    buf = request.SerializeToString()
    length = struct.pack('>L', len(buf))
    socket.sendall(length + buf)

def recv_response(socket):
    length = socket.recv(4)
    length = struct.unpack('>L', length)[0]
    buf = socket.recv(length)
    status = Status()
    status.ParseFromString(buf)
    return status
