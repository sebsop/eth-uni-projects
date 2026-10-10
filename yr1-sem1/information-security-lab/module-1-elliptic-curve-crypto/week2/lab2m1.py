import json
import logging
import socket
import os
import sys
import itertools
from sage.all import Matrix, identity_matrix, zero_matrix, ZZ, block_matrix, diagonal_matrix
from schnorr import Schnorr, Schnorr_Params, Point, Curve

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

s = socket.socket()

fd = s.makefile("rw")

if "REMOTE" in os.environ:
    s.connect(("aclabs.ethz.ch", 55210))
else:
    s.connect(("localhost", 55210))


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

def solve(h, s):
    """Send an answer for the current task and print what the server makes of it."""

    json_send({"command": "solve", "h": h, "s": s})
    res = json_recv()
    logging.info(res)
    if "flag" in res:
        print(res["flag"])
        sys.exit(0)
    return res

a = 0xfffffffffffffffffffffffffffffffefffffffffffffffc
b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
P_x = 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012
P_y = 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811
q = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831

nistp192_params = Schnorr_Params(a, b, p, P_x, P_y, q)
schnorr = Schnorr(nistp192_params)

json_send({"command": "get_pubkey"})
received = json_recv()

public_key = Point(nistp192_params.curve, received["x"], received["y"])

shortest_records = []
total_requests_sent = 0

ideal_amount_of_short_records = 50
digit_treshold = 56
batch_amount = 200

while len(shortest_records) <= ideal_amount_of_short_records and total_requests_sent < 10000:
    count = min(batch_amount, 10000 - total_requests_sent)
    for _ in range(count):
        json_send({"command": "get_signature", "msg": "dosqas"})

    for _ in range(count):
        received = json_recv()

        record = bytes.fromhex(received["record"])
        record_digits = len(record) - 12 - 16

        if record_digits <= digit_treshold:
            h = received["h"]
            s = received["s"]
            shortest_records.append((record_digits, int(h), int(s)))

shortest_records.sort(key=lambda record: record[0])

n = min(ideal_amount_of_short_records, len(shortest_records))
shortest_records = shortest_records[:n]

max_digit_count = shortest_records[-1][0]
bound = 10 ** max_digit_count

weights = [q * 10 ** (max_digit_count - digit_count) for (digit_count, h, s) in shortest_records]

top_left = diagonal_matrix(ZZ, [q * weights[i] for i in range(n)])
bottom_left = Matrix(ZZ, 2, n)
for index, (digit_count, h, s) in enumerate(shortest_records):
    bottom_left[0, index] = h * weights[index]
    bottom_left[1, index] = (s - 10 ** digit_count // 2) * weights[index]

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

potential_h, potential_s = schnorr.Sign(int(private_key), message)

solve(int(potential_h), int(potential_s))