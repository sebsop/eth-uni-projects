import json
import logging
import socket
import os
import sys
import itertools
from sage.all import Matrix, identity_matrix, zero_matrix, ZZ, block_matrix, diagonal_matrix
from schnorr import Schnorr, Schnorr_Params, Point, Curve
import hashlib

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

s = socket.socket()

fd = s.makefile("rw")

if "REMOTE" in os.environ:
    s.connect(("aclabs.ethz.ch", 55220))
else:
    s.connect(("localhost", 55220))


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

def solve(h, s, curve):
    """Send an answer for the current task and print what the server makes of it."""

    json_send({"command": "solve", "h": h, "s": s, "curve": curve})
    res = json_recv()
    logging.info(res)
    if "flag" in res:
        print(res["flag"])
        sys.exit(0)
    return res

a = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc
b = 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
p = 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
P_x = 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66
P_y = 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650
q = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409

nistp521_params = Schnorr_Params(a, b, p, P_x, P_y, q)
schnorr = Schnorr(nistp521_params)

json_send({"command": "get_pubkey", "curve": "P-521"})
received = json_recv()

public_key = Point(nistp521_params.curve, received["x"], received["y"])

records = []

n = 100

for indec in range(n):
    json_send({"command": "get_signature", "curve": "P-521", "msg": f"msg{indec}"})

for _ in range(n):
    received = json_recv()

    h = received["h"]
    s = received["s"]
    records.append((int(h), int(s)))

bound = 2 ** 512

top_left = diagonal_matrix(ZZ, [q ** 2 for _ in range(n)])
bottom_left = Matrix(ZZ, 2, n)
for index in range(n):
    bottom_left[0, index] = records[index][0] * q
    bottom_left[1, index] = (records[index][1] - bound // 2) * q

constant_column_weight = q * bound // 2
bottom_right = Matrix(ZZ, [[bound, 0], [0, constant_column_weight]])
top_right = zero_matrix(n, 2)

matrix = block_matrix([
    [top_left, top_right],
    [bottom_left, bottom_right]
])

reduced_matrix = matrix.LLL()

private_key = None

for index in range(reduced_matrix.nrows()):
    row = reduced_matrix[index]
    last_value = row[-1]

    if abs(last_value) == constant_column_weight:
        if last_value > 0:
            sign = 1
        else: 
            sign = -1

        potential_private_key = ZZ(sign * row[-2] // bound) % q

        if potential_private_key * schnorr.P == public_key:
            private_key = potential_private_key
            break

        if (-potential_private_key) % q * schnorr.P == public_key:
            private_key = (-potential_private_key) % q
            break

message = "gimme the flag"

potential_h, potential_s = schnorr.Sign(int(private_key), message, hash_func=hashlib.sha512)

solve(int(potential_h), int(potential_s), "P-521")