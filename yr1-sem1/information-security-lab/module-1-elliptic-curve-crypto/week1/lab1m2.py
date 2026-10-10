import json
import logging
import socket
import os
import sys
import itertools
from sage.all import EllipticCurve, GF, crt

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

s = socket.socket()

fd = s.makefile("rw")

if "REMOTE" in os.environ:
    s.connect(("aclabs.ethz.ch", 55120))
else:
    s.connect(("localhost", 55120))


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

    json_send({"command": "flag", "x": answer})
    res = json_recv()
    logging.info(res)
    if "flag" in res:
        print(res["flag"])
        sys.exit(0)
    return res

PRIMES = [11, 13, 17, 19]
exponents = {}

json_send({"command": "get_challenge"})
received = json_recv()
P = received["P"]
Q = received["Q"]

def find_exponents():
    for prime in PRIMES:
        product_of_other_primes = 1
        for p in PRIMES:
            if p != prime:
                product_of_other_primes *= p ** 40

        json_send({"command": "mul", "a": product_of_other_primes, "B": P})
        isolated_point = json_recv()["ctxt"]

        json_send({"command": "mul", "a": prime ** 40, "B": isolated_point})
        zero = json_recv()["ctxt"]

        current_factor = 40
        for ei in range(41):
            json_send({"command": "mul", "a": prime ** ei, "B": isolated_point})
            result = json_recv()["ctxt"]

            if result == zero:
                found_ei = ei
                break
        
        exponents[prime] = found_ei

find_exponents()

def compute_previous_contributions(digits, prime, i):
    total = 0

    for j in range(i):
        total += digits[j] * (prime ** j)

    return total

def solve_prime_power(prime):
    e = exponents[prime]
    digits = []

    product_of_other_primes = 1
    for p in PRIMES:
        if p != prime:
            product_of_other_primes *= p ** 40

    json_send({"command": "mul", "a": product_of_other_primes, "B": P})
    current_P = json_recv()["ctxt"]

    json_send({"command": "mul", "a": product_of_other_primes, "B": Q})
    current_Q = json_recv()["ctxt"]

    for i in range(e):
        x_i = 0

        scale_factor = prime ** (e - 1 - i)

        json_send({"command": "mul", "a": scale_factor, "B": current_Q})
        Q_prime = json_recv()["ctxt"]

        previous_contribution = compute_previous_contributions(digits, prime, i)

        for k in range(prime):
            candidate_x = previous_contribution + (k * (prime ** i))

            json_send({"command": "mul", "a": candidate_x * scale_factor, "B": current_P})

            if json_recv()["ctxt"] == Q_prime:
                x_i = k
                break
    
        digits.append(x_i)
    
    residue = compute_previous_contributions(digits, prime, len(digits))

    return residue

def get_result():
    residues = []
    moduli = []

    for prime in PRIMES:
        residue = solve_prime_power(prime)
        residues.append(residue)
        moduli.append(prime ** exponents[prime])

    x = crt(residues, moduli)
    return int(x)

x = get_result()
solve(x)