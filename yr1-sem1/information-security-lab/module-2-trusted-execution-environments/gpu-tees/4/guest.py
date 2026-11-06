import socket
import helper
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from donotmodify import *
import sys
import pickle
from time import sleep
import os

confidential = 0

node_name_map = {}
TIMEOUT = 10


def check_sign_guest(msg):
    if msg[helper.SIGLEN:helper.SIGLEN+len(b'DMA')] == b'DMA': # DMA replies are not signed.
        return 1

    sig_hex = msg[:helper.SIGLEN].decode()

    public_key = ECC.import_key(open("keys/public_guest.pem").read())

    sig = bytes.fromhex(sig_hex)
    verifier = eddsa.new(public_key, 'rfc8032')

    try:
        verifier.verify(msg[helper.SIGLEN:], sig)
        return 1
    except (ValueError, TypeError):
        print("The signature is not valid.")
        return 0

seq_nonce = None

def dma_enc(seq): # Encrypts DMA commands
    global seq_nonce
    s_splitted = seq.split(b":")
    label = s_splitted[2]
    aad = seq_nonce + b":" + label
    s_data = helper.enc_aes(s_splitted[3], "keys/guest_aes_key.bin", aad)
    return b":".join(s_splitted[:3])+b":"+s_data

def sequence_exec(seq_num, client_socket):
    global seq_nonce
    with open('keys/sequence_'+seq_num+'.pkl', 'rb') as f:
        sequence = pickle.load(f)
    with open('keys/expected_reply_'+seq_num+'.pkl', 'rb') as f:
        expected_reply = pickle.load(f)

    global confidential
    node_name = -1
    sequence_num = 1
    timeout_counter = 0
    for i,s in enumerate(sequence):
        wait_cmd = False
        s = s.encode()
        if s == b'CONFIDENTIAL-ON':
            seq_nonce = os.urandom(8).hex().encode()
            s = b'CONFIDENTIAL-ON:' + seq_nonce
        
        if s == b'RESET-KEYS':
            reset_nonce = os.urandom(8).hex().encode()
            s = b'RESET-KEYS:' + reset_nonce

        if confidential and s[0:6] == b"DMA:IN":
            s = dma_enc(s)
        if s[0:len(b"EXEC-CHECK")] == b"EXEC-CHECK" or s[0:len(b"WAIT-FOR-MODEL")] == b"WAIT-FOR-MODEL":
            wait_cmd = True
        
        if s[:6] == b'QUEUE:':
            queue_nonce = os.urandom(8).hex().encode()
            s = s + b':' + queue_nonce
            node_name = s.split(b':')[2]
            node_name_map[node_name] = ""

        if s[0:3] != b'DMA':
            sign = helper.sign_mmio(s, "guest").encode()
        else: # DMA commands are not signed
            dma_cmd_split = s.split(b':')
            dma_cmd_split[2] = node_name_map[dma_cmd_split[2]]
            s = b":".join(dma_cmd_split)
            sign = b'\x00'*helper.SIGLEN 

        dma_out_label = None
        if s[:7] == b'DMA:OUT':
            dma_out_label = s.split(b':')[2]

        client_socket.sendall(sign+s)
        data = client_socket.recv(1024)
        reply = data[helper.SIGLEN:]
        reply_cmd = reply.split(b':')[0].decode()

        if reply_cmd != expected_reply[i]:

            if wait_cmd: # certain commands wait for a specific reply, so we keep sending the command until we get the expected reply or timeout
                client_socket.settimeout(5)
                while reply_cmd != expected_reply[i]:
                    sleep(1)
                    if expected_reply[i] == "EXEC-CHECK-DONE":
                        timeout_counter = timeout_counter + 1
                        if timeout_counter > TIMEOUT:
                            print(f"Timeout reached while waiting for {expected_reply[i]}, stopping the execution")
                            exit(0)
                    client_socket.sendall(sign+s)
                    try:
                        data = client_socket.recv(1024)
                    except socket.timeout:
                        print(f"Timeout reached while waiting for {expected_reply[i]}, stopping the execution")
                        exit(0)
                    reply = data[helper.SIGLEN:]
                    reply_cmd = reply.split(b':')[0].decode()
                client_socket.settimeout(None)
            
            else:
                print(f'GPU replied with {reply_cmd} instead of {expected_reply[i]}, stopping the execution')
                break

        if reply_cmd == 'CONFIDENTIAL-SET':
            confidential = 1

        if not check_sign_guest(data):
            print(f"Signature verification failed for {data}, stopping the execution")
            break

        if reply[:len(b'ACK:Node')] == b'ACK:Node':
            echoed_nonce = reply.split(b':')[-1]
            if echoed_nonce != queue_nonce:
                print("Stale/replayed ACK detected!")
                exit(-1)
                
            node_addr = reply.split(b':')[2]
            assert(node_name != -1)
            # Populates node map
            node_name_map[node_name] = node_addr
        
        if reply[:len(b'KEYS-RESET')] == b'KEYS-RESET':
            echoed_nonce = reply.split(b':')[-1]
            if echoed_nonce != reset_nonce:
                print("Stale/replayed ACK detected!")
                exit(-1)

        if reply[:len(b'CONFIDENTIAL-SET')] == b'CONFIDENTIAL-SET':
            echoed_nonce = reply.split(b':')[-1]
            if echoed_nonce != seq_nonce:
                print("Stale/replayed CONFIDENTIAL-SET detected!")
                exit(-1)

        if confidential and reply[:len(b"DMA-OUT-DONE")] == b"DMA-OUT-DONE":
            data_split = reply.split(b":")
            cipher_fixed = b":".join(data_split[2:]) # join the command in case the ciphertext, tag or nonce contains the symbol ":"

            aad = seq_nonce + b':' + dma_out_label
            value = helper.dec_aes(data_split[1].decode(),cipher_fixed, "keys/guest_aes_key.bin", aad).decode()

            value_split = value.split(':')
            if value_split[0] == 'RES':
                if sys.argv[1] == "2":
                    print(f"Result {sequence_num} is {value_split[1]}", end=";")
                if sequence_num == 2:
                    print("\n", end="")
                sequence_num = sequence_num + 1
            else:
                print(f'ERROR: Keyword RES is not prepended to the result reply')
                exit(-1)

    confidential = 0


def start_guest():
    if len(sys.argv) != 2:
        print("Usage : python guest.py {Sequence to be executed, 1 or 2}")
        exit(1)

    # Clean previous keys
    helper.remove_file("keys/guest_aes_key.bin")
    helper.remove_file("keys/private_guest.pem")
    helper.remove_file("keys/public_guest.pem")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hypervisor_address = ('localhost', GUEST_SOCKET)
    helper.connect(client_socket,hypervisor_address)

    # No key exchange, we are letting the gpu and the guest read the key files
    helper.gen_aes_key("guest")
    helper.gen_ecc_key("guest")
    
    try:
        seq_num = sys.argv[1]
        sequence_exec(seq_num, client_socket)
    finally:
        client_socket.close()

if __name__ == "__main__":
    start_guest()

