import socket
import threading
import helper
from donotmodify import *
import select
from Crypto.PublicKey import ECC
import gpu

ATTACK = 1

attack_sequence_number = 0
dma_in_count = 0
command_counter = 0
reset_keys_counter = 0

ack_msg = None
key_reset_msg = None

value_of_10 = None
value_of_7 = None
value_of_2 = None
value_of_minus_2 = None
value_of_minus_5 = None
value_of_minus_7105 = None
value_of_minus_14758 = None

def dma_in(label, number):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hypervisor_address = ('localhost', DMASOCKET)
    helper.connect(client_socket,hypervisor_address)

    msg = b'\x00'*helper.SIGLEN + b"DMA:IN:D" + str(label).encode() + b":" + number
    client_socket.sendall(msg)
    reply = client_socket.recv(1024)
    client_socket.close()

def record_data(data):
    global value_of_minus_14758, value_of_minus_7105, value_of_minus_2, value_of_2
    global value_of_minus_5, value_of_10, value_of_7

    body = data[128:]
    _, _, label, number_encoding = body.split(b':', 3)
    node = int(label[1:])

    if attack_sequence_number == 1:
        match node:
            case 1:
                value_of_minus_14758 = number_encoding
            case 2:
                value_of_minus_7105 = number_encoding
            case 3:
                value_of_minus_2 = number_encoding
            case 4:
                value_of_2 = number_encoding
    else:
        match node:
            case 1:
                value_of_minus_5 = number_encoding
            case 2:
                value_of_10 = number_encoding
            case 3:
                value_of_7 = number_encoding

clients = {MODEL_PROVIDER_SOCKET: None, GPU_SOCKET: None, GUEST_SOCKET: None}

def check_if_replace_dma(dma_in_count):
    if ATTACK == 1:
        if (dma_in_count == 4):
            dma_in(1, value_of_2)
            dma_in(2, value_of_2)
        elif (dma_in_count == 7):
            dma_in(1, value_of_10)
            dma_in(2, value_of_7)
            dma_in(3, value_of_2)
    elif ATTACK == 2:
        if (dma_in_count == 4):
            dma_in(2, value_of_2)
        elif (dma_in_count == 7):
            dma_in(1, value_of_10)
            dma_in(2, value_of_7)
    elif ATTACK == 3:
        if (dma_in_count == 7):
            dma_in(1, value_of_minus_14758)
            dma_in(2, value_of_10)


def handle_client(connection, client_address, dma_socket, socket_port):
    global dma_in_count

    try:
        clients[socket_port] = connection
        while True:
            data = connection.recv(1024)
            if data:
                # If the incoming request is a DMA command, the hypervisor
                # sends it to the dma controller
                if b'DMA:IN' in data in data:
                    dma_in_count += 1
                    record_data(data)
                    dma_socket.sendall(data)
                    msg = dma_socket.recv(1024)
                    connection.sendall(b'\x00'*helper.SIGLEN+msg)
                    check_if_replace_dma(dma_in_count)
                elif b'DMA:OUT' in data:
                    dma_socket.sendall(data)
                    msg = dma_socket.recv(1024)
                    connection.sendall(b'\x00'*helper.SIGLEN+msg)
                else:
                    relay_message(connection, data)
            else:
                break
    except Exception as e:
        print(e)
    finally:
        connection.close()

def send_ack(client):
    client.sendall(ack_msg)

def relay_message(sender, message): # Relays the message to the guest, model provider or GPU depending on the sender
    # if the sender is the model provider or the guest, relay the message to the GPU
    global command_counter
    global ack_msg
    global attack_sequence_number
    global reset_keys_counter, key_reset_msg

    if message[helper.SIGLEN:helper.SIGLEN+10] == b'RESET-KEYS':
        attack_sequence_number += 1

    if sender == clients[MODEL_PROVIDER_SOCKET] or sender == clients[GUEST_SOCKET]:
        command_counter += 1
        
        try:
            if ATTACK == 1:
                if command_counter > 11 and command_counter <= 16:
                    send_ack(sender)
                    return                
            elif ATTACK == 2:
                if (command_counter > 11 and command_counter <= 16) or command_counter == 32:
                    send_ack(sender)
                    return  
            elif ATTACK == 3:
                if command_counter == 33:
                    send_ack(sender)
                    return  
            if message[128:] == b'RESET-KEYS':
                reset_keys_counter += 1
                if reset_keys_counter == 2:
                    sender.sendall(key_reset_msg)
                    return
            clients[GPU_SOCKET].sendall(message)
        except Exception as e:
            print(e)
            clients[GPU_SOCKET].close()
            del clients[GPU_SOCKET]
    
    # if the sender is the GPU, relay the message to the model provider or the guest depending on the prefix of the message
    elif sender == clients[GPU_SOCKET]:
        if message[0:2].decode() == "M:":

            try:
                message = message[2:]
                clients[MODEL_PROVIDER_SOCKET].sendall(message)
            except Exception:
                clients[MODEL_PROVIDER_SOCKET].close()
                del clients[MODEL_PROVIDER_SOCKET]

        elif message[0:2].decode() == "G:":
            try:
                message = message[2:]
                if message[128:131] == b'ACK':
                    ack_msg = message
                if message[128:] == b'KEYS-RESET':
                    key_reset_msg = message
                clients[GUEST_SOCKET].sendall(message)
            except Exception:
                clients[GUEST_SOCKET].close()
                del clients[GUEST_SOCKET]
    else: print(sender)


def start_hypervisor():
    dma_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dma_address = ('localhost', DMASOCKET)
    helper.connect(dma_socket,dma_address)

    socket_dict = {}
    for sockets in [GPU_SOCKET, GUEST_SOCKET, MODEL_PROVIDER_SOCKET]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        hypervisor_address = ('localhost', sockets)
        s.bind(hypervisor_address)
        s.listen(2)
        socket_dict[s] = sockets

    while True:
        readable, _, _ = select.select(list(socket_dict.keys()), [], [])

        for hypervisor_socket in readable:
            socket_port = socket_dict[hypervisor_socket]

            connection, client_address = hypervisor_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(connection, client_address, dma_socket, socket_port))
            client_thread.start()


if __name__ == "__main__":
    start_hypervisor()
