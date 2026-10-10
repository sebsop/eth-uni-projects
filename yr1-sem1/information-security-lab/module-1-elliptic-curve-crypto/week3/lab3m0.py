import json
import logging
import socket
import os
import sys
import itertools
from sage.all import PolynomialRing, ZZ, Sequence, inverse_mod, Zmod

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

s = socket.socket()

fd = s.makefile("rw")

if "REMOTE" in os.environ:
    s.connect(("aclabs.ethz.ch", 55300))
else:
    s.connect(("localhost", 55300))


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

def solve(otp):
    """Send an answer for the current task and print what the server makes of it."""

    json_send({"command": "login", "otp": otp, "password": "admin"})
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

OTP_DIGITS = 36

json_send({"command": "get_pubkey"})
received = json_recv()

n = received["n"]
e = received["e"]

json_send({"command": "send_otp"})
received = json_recv()
encrypted_otp = int(received["ciphertext"], 16)

prefix = '{"user": "admin", "otp": "'
prefix_bytes = prefix.encode()
prefix_int = int.from_bytes(prefix_bytes, "big")

suffix = '", "valid_for": 300}'
suffix_bytes = suffix.encode()
suffix_int = int.from_bytes(suffix_bytes, "big")

base_otp_int = int.from_bytes(b'0' * OTP_DIGITS, "big")

otp_offset_needed = 256 ** len(suffix_bytes)
prefix_offset_needed = 256 ** (len(suffix_bytes) + OTP_DIGITS)

constant_part = prefix_int * prefix_offset_needed + base_otp_int * otp_offset_needed + suffix_int

R = PolynomialRing(ZZ, 1, 'x', implementation='singular')
x = R.gen()
F = (constant_part + x * otp_offset_needed) ** 3 - encrypted_otp

leading_coefficient = int(F.leading_coefficient())
inverse_of_leading_coefficient = inverse_mod(leading_coefficient, n)
F = inverse_of_leading_coefficient * F
F = F.change_ring(Zmod(n)).change_ring(ZZ)

X = int.from_bytes(bytes([9] * OTP_DIGITS), "big")

roots = coppersmith(F, n, X)

recovered_otp_int = roots[0]
full_otp_int = base_otp_int + recovered_otp_int
recovered_otp = full_otp_int.to_bytes(OTP_DIGITS, "big").decode()

solve(recovered_otp)