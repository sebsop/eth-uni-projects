import json
import logging
import socket
import os
import sys
import itertools
from sage.all import PolynomialRing, ZZ, Sequence, inverse_mod, Zmod
import math
from Crypto.Hash import SHA256
from hashlib import shake_256
from poker import BITS_PER_CARD, BOARD_CARDS, HOLE_CARDS, score_hand, deal

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

s = socket.socket()

fd = s.makefile("rw")

if "REMOTE" in os.environ:
    s.connect(("aclabs.ethz.ch", 55320))
else:
    s.connect(("localhost", 55320))


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

def solve(signature):
    """Send an answer for the current task and print what the server makes of it."""

    json_send({"command": "solve", "signature": signature})
    res = json_recv()
    logging.info(res)
    if "flag" in res:
        print(res["flag"])
        sys.exit(0)
    return res


def coppersmith(F, M, X, h=7):
    degree = F.degree()
    R = PolynomialRing(ZZ, 1, 'x', implementation='singular')
    x = R.gen()
    F_R = R(F)

    S = Sequence([], R)
    for j in range(h):
        for i in range(degree):
            polynomial = (M ** (h - 1 - j)) * (F_R ** j) * (x ** i)
            scaled_polynomial = polynomial.subs(x=x * X)
            S.append(scaled_polynomial)

    matrix, monomials = S.coefficients_monomials(sparse=False)
    reduced_matrix = matrix.LLL()
    shortest_vector = reduced_matrix[0]

    exponents = [m.degree() for m in monomials]
    max_exponent = max(exponents)

    G = 0
    for coefficient, exponent in zip(shortest_vector, exponents):
        G += coefficient * X ** (max_exponent - exponent) * x ** exponent

    flint_polynomial = G.univariate_polynomial()
    raw_roots = flint_polynomial.roots(multiplicities=False)

    valid_roots = [r for r in raw_roots if F(r) % M == 0]
    return valid_roots

SEED_LENGTH_BYTES = 768 // 8
COMMITMENT_LENGTH_BYTES = 512 // 8
TARGET_EXPONENT = 128
UNKNOWN_BITS = (SEED_LENGTH_BYTES - COMMITMENT_LENGTH_BYTES) * 8

def deal_round(randomness: int):
    n_cards = 2 * HOLE_CARDS + BOARD_CARDS
    whitened = shake_256(randomness.to_bytes(SEED_LENGTH_BYTES, "big")).digest(math.ceil(n_cards * BITS_PER_CARD / 8))
    cards = deal(int.from_bytes(whitened, "big"), n_cards)
    return cards[:HOLE_CARDS], cards[HOLE_CARDS:2 * HOLE_CARDS], cards[2 * HOLE_CARDS:]

json_send({"command": "info"})
info = json_recv()
modulus = info["modulus"]

N = int(modulus)
commitment_hex = info["commitment"]
challenger = info["challenger"]

S_known = int(commitment_hex, 16) << UNKNOWN_BITS

seed = None
while seed is None:
    i_this_round = challenger

    json_send({"command": "all_in"})
    received = json_recv()

    if "debug" in received:
        r = int(received["debug"]["prng_output"])

        R = PolynomialRing(ZZ, 'x')
        x = R.gen()
        base = S_known + i_this_round
        F = (x + base) ** 2 - r
        X = 1 << UNKNOWN_BITS

        roots = coppersmith(F, N, X)
        u = roots[0] % N
        seed = S_known + u
    
    if "flag" in received:
        print(received["flag"])
        sys.exit(0)
    
    challenger = received.get("challenger")
    if challenger is None:
        json_send({"command": "cash_out"})
        received = json_recv()
        if "flag" in received:
            print(received["flag"])
        sys.exit(0)

while True:
    i_this_round = challenger
    r_pred = pow(seed + i_this_round, 2, N)
    my_hole, challenger_hole, board = deal_round(r_pred)

    my_score = score_hand(my_hole + board)
    challenger_score = score_hand(challenger_hole + board)

    if (my_score > challenger_score):
        json_send({"command": "all_in"})
    else:
        json_send({"command": "fold"})

    received = json_recv()
    if "flag" in received:
        print(received["flag"])
        sys.exit(0)

    challenger = received.get("challenger")
    
    if challenger is None:
        json_send({"command": "cash_out"})
        received = json_recv()
        if "flag" in received:
            print(received["flag"])
        sys.exit(0)

    def parse_balance(balance_string):
        return int(balance_string.split("^", 1)[1])

    ballance = received.get("balance")
    if ballance is not None and parse_balance(ballance) >= TARGET_EXPONENT:
        json_send({"command": "cash_out"})
        received = json_recv()
        if "flag" in received:
            print(received["flag"])
        sys.exit(0)


