import socket
import threading
import helper
from donotmodify import *
import select
import time

clients = {MODEL_PROVIDER_SOCKET: None, GPU_SOCKET: None, GUEST_SOCKET: None}

def dma_out(label):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hypervisor_address = ('localhost', DMASOCKET)
    helper.connect(client_socket,hypervisor_address)
    client_socket.sendall(b'\x00'*helper.SIGLEN+f"DMA:OUT:{label}".encode())
    reply = client_socket.recv(1024)
    client_socket.close()
    value = reply.split(b':', 1)[1]
    return float(value)

def extract_model():
    model = []

    for i in range(0, 10):
        weight = dma_out(f"O{i}")
        model.append(int(weight))

    print(model)

def handle_client(connection, client_address, dma_socket, socket_port):
    try:
        clients[socket_port] = connection
        while True:
            data = connection.recv(1024)
            if data:
                # If the incoming request is a DMA command, the hypervisor
                # sends it to the dma controller
                if b'DMA:IN' in data or b'DMA:OUT' in data:
                    dma_socket.sendall(data)
                    msg = dma_socket.recv(1024)
                    connection.sendall(b'\x00'*helper.SIGLEN+msg)
                else:
                    relay_message(connection, data)
            else:
                break
    finally:
        connection.close()

exec_pause_msg = None
pause_count = 0
resume_count = 0
token_count_response = None
token_count_count = 0

def relay_message(sender, message): # Relays the message to the guest, model provider or GPU depending on the sender
    global pause_count, exec_pause_msg, resume_count, token_count_response, token_count_count

    # if the sender is the model provider or the guest, relay the message to the GPU
    if sender == clients[MODEL_PROVIDER_SOCKET] or sender == clients[GUEST_SOCKET]:

        try:
            cmd = message[128:].split(b':', 1)[0]

            if cmd == b'PAUSE':
                pause_count += 1

                if (pause_count in [2, 3]):
                    sender.sendall(exec_pause_msg)
                    return

            if cmd == b'RESUME':
                resume_count += 1
                
                if resume_count == 3:
                    extract_model()
                    return

            if cmd == b'TOKEN-COUNT':
                token_count_count += 1
                
                if token_count_count in [2, 3]:
                    sender.sendall(token_count_response)
                    return

            clients[GPU_SOCKET].sendall(message)
        except Exception as e:
            print(e)
            clients[GPU_SOCKET].close()
            del clients[GPU_SOCKET]
    
    # if the sender is the GPU, relay the message to the model provider or the guest depending on the prefix of the message
    elif sender == clients[GPU_SOCKET]:
        if message[0:2].decode() == "M:":
            cmd = message[130:].split(b':', 1)[0]

            try:
                message = message[2:]
                if cmd == b'EXEC-PAUSE':
                    exec_pause_msg = message
                if cmd == b'TOKEN-COUNT-DONE':
                    token_count_response = message

                clients[MODEL_PROVIDER_SOCKET].sendall(message)
            except Exception:
                print(e)
                clients[MODEL_PROVIDER_SOCKET].close()
                del clients[MODEL_PROVIDER_SOCKET]

        elif message[0:2].decode() == "G:":

            try:
                message = message[2:]
                clients[GUEST_SOCKET].sendall(message)
            except Exception:
                print(e)
                clients[GUEST_SOCKET].close()
                del clients[GUEST_SOCKET]


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
