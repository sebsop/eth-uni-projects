import json
import logging
import socket
import os
import sys
import itertools
from sage.all import Matrix, identity_matrix, zero_matrix, ZZ, block_matrix

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

s = socket.socket()

fd = s.makefile("rw")

if "REMOTE" in os.environ:
    s.connect(("aclabs.ethz.ch", 55200))
else:
    s.connect(("localhost", 55200))


def json_recv():
    """Receive a serialized json object from the server and deserialize it"""

    line = fd.readline()
    logging.debug(f"Recv: {line}")
    return json.loads(line)


def json_send(obj):
    """Convert the object to json and send to the server"""

    request = json.dumps(obj)
    logging.debug(f"Send: {request}")
    fd.write(request + "\n")
    fd.flush()

def solve(answer):
    """Send an answer for the current task and print what the server makes of it."""

    json_send({"command": "flag", "token": answer})
    res = json_recv()
    logging.info(res)
    if "flag" in res:
        print(res["flag"])
        sys.exit(0)
    return res

json_send({"command": "get_challenge"})
received = json_recv()

public_key = received["pk"]
encrypted_token = received["enc_token"]

n = 64

top_left = identity_matrix(n)
bottom_left = zero_matrix(ZZ, 1, n)
bottom_right = Matrix(ZZ, [[encrypted_token]])

neg_public_key = [[-b] for b in public_key]
top_right = Matrix(ZZ, n, 1, neg_public_key)

matrix = block_matrix([
    [top_left, top_right],
    [bottom_left, bottom_right]
])

reduced_matrix = matrix.LLL()

reduced_vector = reduced_matrix[0]

bits = [abs(int(reduced_vector[i])) for i in range(n)]

token = 0
for index, bit in enumerate(bits):
    token |= (bit << index)

solve(token)