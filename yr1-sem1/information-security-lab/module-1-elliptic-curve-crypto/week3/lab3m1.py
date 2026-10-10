import json
import logging
import socket
import os
import sys
import itertools
from sage.all import PolynomialRing, ZZ, Sequence, inverse_mod, Zmod
import math
from Crypto.Hash import SHA256
import hashlib

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

s = socket.socket()

fd = s.makefile("rw")

if "REMOTE" in os.environ:
    s.connect(("aclabs.ethz.ch", 55310))
else:
    s.connect(("localhost", 55310))


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


def coppersmith(F, M, X, h=7, t=7):
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

    for i in range(1, t):
        polynomial = (F_R ** (h - 1)) * (x ** i)
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

    valid_roots = [r for r in raw_roots if math.gcd(int(F(r)), int(M)) > 1]
    return valid_roots

def first_primes(count: int) -> list[int]:
    primes = []
    candidate = 2
    while len(primes) < count:
        if all(candidate % p != 0 for p in primes):
            primes.append(candidate)
        candidate += 1
    return primes

WHEEL = math.prod(first_primes(50))

def wheel_residue(index: int) -> int:
    """ Deterministically derive a residue that is coprime to the wheel """
    counter = 0
    while True:
        seed = f"FastPrime(TM) residue {index}/{counter}".encode()
        r = int.from_bytes(hashlib.shake_256(seed).digest(64)) % WHEEL
        if math.gcd(r, WHEEL) == 1:
            return r
        counter += 1

RESIDUES = [wheel_residue(i) for i in range(64)]

json_send({"command": "get_pubkey"})
received = json_recv()

n = received["n"]
e = received["e"]

target_value = n % WHEEL
pairs = []
for i in range(len(RESIDUES)):
    for j in range(i + 1, len(RESIDUES)):
        if (RESIDUES[i] * RESIDUES[j]) % WHEEL == target_value:
            pairs.append((RESIDUES[i], RESIDUES[j]))

R = PolynomialRing(ZZ, 1, 'x', implementation='singular')
x = R.gen()

X = 2 ** (512 - WHEEL.bit_length() + 1)

WHEEL_inverse = inverse_mod(WHEEL, n)

p = None
for pair in pairs:
    for r in pair:
        F = x + (r * WHEEL_inverse) % n
        for k in coppersmith(F, n, X):
            candidate = k * WHEEL + r
            if (candidate > 1) and (n % candidate == 0):
                p = candidate
                break
        if p:
            break
    if p:
        break;

q  = n // p

product = (p - 1) * (q - 1)
d = inverse_mod(e, product)
h = int.from_bytes(SHA256.new(b"gimme the flag").digest())
signature = pow(h, int(d), n)

solve(signature)