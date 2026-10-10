import json
import logging
import socket
import os
import sys
import itertools
from sage.all import EllipticCurve, GF

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

s = socket.socket()

fd = s.makefile("rw")

if "REMOTE" in os.environ:
    s.connect(("aclabs.ethz.ch", 55110))
else:
    s.connect(("localhost", 55110))


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

    json_send({"command": "flag", "privkey": answer})
    res = json_recv()
    logging.info(res)
    if "flag" in res:
        print(res["flag"])
        sys.exit(0)
    return res


a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P_x = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P_y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
K = GF(p)
curve = EllipticCurve(K, (K(a), K(b)))
P = curve(P_x, P_y)
curve.set_order(q)

candidate_upper_half_points = {}

def create_hash_table(upper_half_of_privkey):
    for bits_to_flip in itertools.combinations(range(128), 3):
        candidate_upper_half_of_privkey = upper_half_of_privkey

        for bit_index in bits_to_flip:
            candidate_upper_half_of_privkey ^= (1 << bit_index)

        candidate_upper_half_points[P * (candidate_upper_half_of_privkey << 128)] = candidate_upper_half_of_privkey << 128

def validate_privkey(pubkey, candidate_lower_half_of_privkey):
    candidate_lower_half_point = P * candidate_lower_half_of_privkey
    needed_complement = pubkey - candidate_lower_half_point

    if (needed_complement in candidate_upper_half_points):
        upper_half = candidate_upper_half_points[needed_complement]
        solve(candidate_lower_half_of_privkey + upper_half)


def find_correct_privkey(pubkey, leaked_privkey):
    create_hash_table(leaked_privkey >> 128)

    lower_half_of_privkey = leaked_privkey & ((1 << 128) - 1)

    for bits_to_flip in itertools.combinations(range(128), 3):
        candidate_lower_half_of_privkey = lower_half_of_privkey

        for bit_index in bits_to_flip:
            candidate_lower_half_of_privkey ^= (1 << bit_index)
    
        validate_privkey(pubkey, candidate_lower_half_of_privkey)


json_send({"command": "get_leak"})
leaked_privkey = json_recv()["leak"]

json_send({"command": "get_pubkey"})
pubkey_data = json_recv()
pubkey = curve(pubkey_data["x"], pubkey_data["y"])

find_correct_privkey(pubkey, leaked_privkey)