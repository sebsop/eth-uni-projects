import socket
import helper
from donotmodify import *
import pickle
from dram_store import dram_lock, load_dram, store_dram
import threading, time

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

class Node:
    def __init__(self, op_type, input_addr_list, output_addr):
        self.op_type = op_type
        self.output_addr = output_addr
        self.input_addr_list = input_addr_list

compute_list = []

queue_started = 0
confidential = 0
execution_running = 0
execution_done = 0

enc_model_pointer = []
dec_model_pointer = []
token_counter = 0
ENCRYPTED_MODEL_ADDRESS_PREFIX = "F"
DECRYPTED_MODEL_ADDRESS_PREFIX = "O"


def map_continuous_addr_range(size, map_encrypted_model):
    global enc_model_pointer
    global dec_model_pointer

    with dram_lock():
        dram = load_dram()

        if map_encrypted_model:
            op_output_list = [ENCRYPTED_MODEL_ADDRESS_PREFIX+str(i) for i in range(len(enc_model_pointer), len(enc_model_pointer)+size)]
        else:
            op_output_list = [DECRYPTED_MODEL_ADDRESS_PREFIX+str(i) for i in range(len(dec_model_pointer), len(dec_model_pointer)+size)]

        free_addrs = []
        for d in dram["MEMORY"]:
            if dram["MEMORY"][d] == -1:
                free_addrs.append(d)
                if len(free_addrs) == size:
                    for i in range(size):
                        dram["MEMORY"][free_addrs[i]] = 0
                        dram["ADDRESS_MAP"][op_output_list[i]] = free_addrs[i]
                    store_dram(dram)
                    return op_output_list

    print("ERROR: Memory space exhausted, unable to find a continuous range of free addresses of size", size)
    exit(-1)
    return []

def map_addr(op_output):
    with dram_lock():
        dram = load_dram()

        if op_output in dram["ADDRESS_MAP"]:
            return

        for d in dram["MEMORY"]:
            if dram["MEMORY"][d] == -1:
                dram["MEMORY"][d] = 0
                dram["ADDRESS_MAP"][op_output] = d
                store_dram(dram)
                return

    print("ERROR: Memory space exhausted, unable to find a free address")
    exit(-1)

def protect_memory_range(addr_list):
    with dram_lock():
        dram = load_dram()
        dram["PROTECTION_RANGE"] = addr_list
        store_dram(dram)

def remove_protection_range():
    with dram_lock():
        dram = load_dram()
        dram["PROTECTION_RANGE"] = []
        store_dram(dram)

def resolve_mapped_addr(addr):
    with dram_lock():
        dram = load_dram()

    if addr in dram["ADDRESS_MAP"]:
        return dram["ADDRESS_MAP"][addr]
    else:
        print(f"ERROR:Address {addr} is not mapped to any physical address")
        exit(-1)

def read_mem(addr):
    global token_counter

    if addr[0] == 'O':
        token_counter += 1

    with dram_lock():
        addr = resolve_mapped_addr(addr)
        dram = load_dram()

        if not addr in dram["MEMORY"]:
            print(f"Invalid read: address {addr} does not exist")
            exit(-1)

        value = dram["MEMORY"][addr]
    if value == -1:
        print(f"Invalid read: address {addr} is not initialized")
        exit(-1)

    return value

def clear_mem(mapped_addr):
    with dram_lock():
        dram = load_dram()

        if not mapped_addr in dram["ADDRESS_MAP"]:
            print(f"Invalid clear: mapped address {mapped_addr} does not exist")
            exit(-1)

        addr = resolve_mapped_addr(mapped_addr)

        dram["MEMORY"][addr] = -1
        del dram["ADDRESS_MAP"][mapped_addr]
        if mapped_addr in dram["PROTECTION_RANGE"]:
            dram["PROTECTION_RANGE"].remove(mapped_addr)

        store_dram(dram)

def write_mem(addr, value):
    with dram_lock():
        addr = resolve_mapped_addr(addr)

        dram = load_dram()

        if not addr in dram["MEMORY"]:
            print(f"Invalid write: address {addr} does not exist")
            exit(-1)

        if not isinstance(value,bytes):
            # Writes a byte string to the memory address
            value = str(value).encode()
        dram["MEMORY"][addr] = value

        store_dram(dram)

def reset_mem():
    with dram_lock():
        dram = load_dram()

        for d in dram["MEMORY"]:
            dram["MEMORY"][d] = -1

        dram["PROTECTION_RANGE"] = []
        dram["ADDRESS_MAP"] = {}

        store_dram(dram)


def send_mmio(socket, msg, is_model_provider=False):
    sign_string = "guest"
    identifier = "G:"
    if is_model_provider:
        sign_string = "model"
        identifier = "M:"

    sign = helper.sign_mmio(msg,sign_string)
    socket.sendall(identifier.encode() + sign.encode() + msg)

def check_sign_gpu(msg, hypervisor_socket, is_model_provider):
    sig_hex = msg[:helper.SIGLEN].decode()
    
    key = "keys/public_guest.pem"
    if is_model_provider:
        key = "keys/public_model.pem"

    public_key = ECC.import_key(open(key).read())

    sig = bytes.fromhex(sig_hex)
    verifier = eddsa.new(public_key, 'rfc8032')

    try:
        verifier.verify(msg[helper.SIGLEN:], sig)
        return 1
    except (ValueError, TypeError):
        print("The signature is not valid.")
        reset()
        message = b"ERROR:Signature is not matching the message"
        send_mmio(hypervisor_socket, message, is_model_provider)
        return 0

def reset_keys(): # Generates new keys
    helper.gen_aes_key("guest")
    helper.gen_ecc_key("guest")

def reset(): # Clears all states
    global execution_running
    global queue_started
    global confidential

    if execution_running:
        return "ERROR:Cannot reset while execution is running"
    compute_list = []
    reset_mem()
    queue_started = 0
    confidential = 0

def add_op(command):
    global execution_running
    global queue_started


    if execution_running:
        return b"ERROR:Execution is already running, cannot add new operations to the compute queue"

    if queue_started:
        message = queue_op(command.decode())
    else:
        message = b"ERROR:Compute queue is not ready to accept new tasks"

    return message

def queue_start():
    global execution_running
    global queue_started

    if execution_running:
        return "ERROR:Cannot start a new queue while execution is running"

    compute_list = []
    queue_started = 1

def queue_stop():
    global execution_running
    global queue_started

    if execution_running:
        return "ERROR:Cannot stop the queue while execution is running"

    queue_started = 0
    message = "QUEUE-DONE"
    
    return message.encode()

def start_exec():
    global execution_running
    global execution_done
    global enc_model_pointer

    if execution_running:
        return "ERROR:Execution is already running"

    if len(enc_model_pointer) != 0:
        decrypt_model()

    execution_done = 0
    execution_running = 1

    return b"EXEC-START-DONE"

def check_if_exec_done():
    global execution_done

    if execution_done:
        return b"EXEC-CHECK-DONE"
    else:
        return b"EXEC-CHECK-NOT-DONE"

def check_if_exec_running():
    global execution_running

    if execution_running:
        return b"EXEC-RUNNING"
    else:
        return b"EXEC-NOT-RUNNING"

def op_2_node(op_inputs, op_output, op_type, nonce): # Operator with 2 inputs
    num_inputs = len(op_inputs)
    message = ""
    map_addr(op_output)

    node = Node(op_type, op_inputs, op_output)

    if num_inputs == 2:
        compute_list.append(node)
        message = f"ACK:Node Op:{op_output}:{nonce}"
    else:
        message = f"ERROR:Operator expects 2 inputs and received {num_inputs}"

    return message

def op_1_node(op_inputs, op_output, op_type, nonce): # Operator with 1 input
    num_inputs = len(op_inputs)
    message = ""
    map_addr(op_output)

    node = Node(op_type, op_inputs, op_output)

    if num_inputs == 1:
        compute_list.append(node)
        message = f"ACK:Node Op:{op_output}:{nonce}"
    else:
        message = f"ERROR:Operator expects 1 inputs and received {num_inputs}"

    return message

def op_data_node(op_output, nonce): # Data node
    map_addr(op_output)

    node = Node("DATA",[], op_output)

    compute_list.append(node)

    return f"ACK:Node Data:{op_output}:{nonce}"

def op_end_node(op_output, nonce):
    map_addr(op_output)

    op_inputs = [compute_list[-1].output_addr]
    node = Node("END", op_inputs, op_output) # Last node added will be the end node

    compute_list.append(node)

    return f"ACK:Node End:{op_output}:{nonce}"

def queue_op(command):
    command_split = command.split(":")

    length_cmd = len(command_split)
    if length_cmd < 4:
        err_msg = f"ERROR:QUEUE command is expecting at least 4 parameters and received {length_cmd} instead"
        return err_msg.encode()

    queue_nonce = command_split[-1]
    command_split = command_split[:-1]
    queue_type = command_split[1]
    op_output = command_split[2]

    match queue_type:
        case "ADD" | "SUB":
            message = op_2_node(command_split[3:], op_output, queue_type, queue_nonce)
        case "ABS" | "INV":
            message = op_1_node(command_split[3:], op_output, queue_type, queue_nonce)
        case "DATA":
            message = op_data_node(op_output, queue_nonce)
        case "END":
            message = op_end_node(op_output, queue_nonce)
        case _:
            message = "UNKNOWN-OP"

    return message.encode()

def decrypt_data(ops, values):
    for i,o in enumerate(ops):
        if confidential:
            length = values[i].split(b':')[0]
            ciphertext = b':'.join(values[i].split(b':')[1:])
            aad = confidential_nonce + b':' + o.encode()
            values[i] = helper.dec_aes(length, ciphertext, "keys/guest_aes_key.bin", aad)

        values[i] = float(values[i])

    return values

def encrypt_result(value, output_label):
    value = b'RES:'+str(value).encode()
    if confidential:
        aad = confidential_nonce + b':' + output_label.encode()
        value = helper.enc_aes(value, "keys/guest_aes_key.bin", aad)

    return value


def do_add(input_addrs):
    left_op = read_mem(input_addrs[0])
    right_op = read_mem(input_addrs[1])

    left_op,right_op = decrypt_data(input_addrs,[left_op,right_op])

    return left_op + right_op

def do_sub(input_addrs):
    left_op = read_mem(input_addrs[0])
    right_op = read_mem(input_addrs[1])

    left_op,right_op = decrypt_data(input_addrs,[left_op,right_op])

    return left_op - right_op

def do_abs(input_addrs):
    op = read_mem(input_addrs[0])

    op = decrypt_data(input_addrs,[op])[0]

    return abs(op)

def do_inv(input_addrs):
    op = read_mem(input_addrs[0])

    op = decrypt_data(input_addrs,[op])[0]

    return -op

def do_end(input_addrs, output_addr):
    last_op = read_mem(input_addrs[0])

    last_op = decrypt_data(input_addrs,[last_op])[0]

    result = encrypt_result(last_op, output_addr)
    return result

def write_encrypted(output_addr, value):
    if confidential:
        aad = confidential_nonce + b':' + output_addr.encode()
        enc = helper.enc_aes(str(value).encode(), "keys/guest_aes_key.bin", aad)
        write_mem(output_addr, enc)
    else:
        write_mem(output_addr, value)

def exec_op():
    op = compute_list[0]
    compute_list.pop(0)

    if op.op_type != "DATA":
        match op.op_type:
            case "ADD":
                result = do_add(op.input_addr_list)
                write_encrypted(op.output_addr,result)
            case "SUB":
                result = do_sub(op.input_addr_list)
                write_encrypted(op.output_addr,result)
            case "ABS":
                result = do_abs(op.input_addr_list)
                write_encrypted(op.output_addr,result)
            case "INV":
                result = do_inv(op.input_addr_list)
                write_encrypted(op.output_addr,result)
            case "END":
                result = do_end(op.input_addr_list, op.output_addr)
                write_mem(op.output_addr,result)
            case _:
                print("Implementation error")
                exit(-1)

confidential_nonce = None

def set_confidential(command):
    global execution_running
    global confidential, confidential_nonce

    if execution_running:
        return "ERROR:Cannot set confidential mode while execution is running"

    confidential = 1
    confidential_nonce = command.split(b':', 1)[1]

def check_if_confidential():
    global confidential

    if confidential:
        return b"CONFIDENTIAL-ON"
    else:
        return b"CONFIDENTIAL-OFF"

def wait_for_model():
    global enc_model_pointer

    if len(enc_model_pointer) != 0:
        return b"WAIT-FOR-MODEL-DONE"
    else:
        return b"WAIT-FOR-MODEL-NOT-DONE"

def gpu_loop(hypervisor_socket):
    global execution_running
    global execution_done

    while True:
        # check if there is an mmio, event, this simulates the interrupt happening
        handle_mmio_event(hypervisor_socket)

        # if a execution is running, but we have no ops, the execution is done
        if execution_running and len(compute_list) == 0:
            execution_done = 1
            execution_running = 0

            if len(dec_model_pointer) != 0:
                clear_decrypted_model()

        # if there is no execution, sleep shortly, before looping again
        if not execution_running:
            continue

        time.sleep(0.1)

        exec_op()

def load_model(command):
    global enc_model_pointer
    global execution_running

    if execution_running:
        return b"ERROR:Cannot load the model while execution is running"

    if len(enc_model_pointer) != 0:
        return b"ERROR:Model is already loaded, please clear the model before loading a new one"

    ciphertext = command.split(b":", 1)[1]

    num_chunks = 10
    chunk_size = (len(ciphertext) + num_chunks - 1)
    chunks = [
        ciphertext[i:i + chunk_size]
        for i in range(0, len(ciphertext), chunk_size)
    ]
    model_size = len(chunks)

    mapped_addrs = [ENCRYPTED_MODEL_ADDRESS_PREFIX+str(i) for i in range(model_size)]
    mapped_addrs = map_continuous_addr_range(model_size, True)

    for addr, chunk in zip(mapped_addrs, chunks):
        write_mem(addr, chunk)

    enc_model_pointer.extend(mapped_addrs)
    return b"LOADED"

def decrypt_model():
    global enc_model_pointer
    global dec_model_pointer

    full_ciphertext = b"".join([read_mem(addr) for addr in enc_model_pointer])

    length = full_ciphertext.split(b":")[0]
    ciphertext = b':'.join(full_ciphertext.split(b":")[1:])
    decrypted_model_str = helper.dec_aes(length, ciphertext, "keys/model_aes_key.bin") # test decryption
    model_values = decrypted_model_str.split(b',')

    dec_model_size = len(model_values)

    mapped_addrs = [DECRYPTED_MODEL_ADDRESS_PREFIX+str(i) for i in range(dec_model_size)]
    mapped_addrs = map_continuous_addr_range(dec_model_size, False)
    protect_memory_range(mapped_addrs)

    for addr, value in zip(mapped_addrs, model_values):
        write_mem(addr, value)

    dec_model_pointer.extend(mapped_addrs)

def clear_decrypted_model():
    global dec_model_pointer
    global execution_running

    if len(dec_model_pointer) == 0:
        return b"ERROR:No decrypted model is loaded, cannot clear"

    for addr in dec_model_pointer:
        clear_mem(addr)

    dec_model_pointer = []


def pause_exec():
    global execution_running
    global dec_model_pointer

    if len(dec_model_pointer) != 0:
        clear_decrypted_model()

    execution_running = 0
    return b"EXEC-PAUSE"

def resume_exec():
    global execution_running
    global enc_model_pointer

    if len(enc_model_pointer) != 0:
        decrypt_model()

    execution_running = 1
    return b"EXEC-RESUME"

def clear_model():
    global enc_model_pointer
    global execution_running

    execution_running = 0

    if len(dec_model_pointer) != 0:
        clear_decrypted_model()

    if len(enc_model_pointer) == 0:
        return b"ERROR:No model is loaded, cannot clear"

    for addr in enc_model_pointer:
        clear_mem(addr)
    
    enc_model_pointer = []
    return b"MODEL-CLEARED"

def check_token_count():
    global token_count

    if execution_running:
        return b"ERROR:Cannot read token counter while the model is running."
    
    return f"TOKEN-COUNT-DONE:{token_counter}".encode()


mmio_memory_tasks = []
def gpu_mmio(data, hypervisor_socket):
    global mmio_memory_tasks

    mmio_memory_tasks.append(data)

def handle_mmio_event(hypervisor_socket):
    global mmio_memory

    if len(mmio_memory_tasks) == 0:
        return

    mmio_memory = mmio_memory_tasks.pop(0)
    message = b"" 

    command = mmio_memory[helper.SIGLEN:]
    command_parsed = command.split(b":")[0].decode()

    is_model_provider = False

    if command_parsed in ["LOAD", "EXEC-RUN", "PAUSE", "CLEAR", "RESUME", "TOKEN-COUNT", "CHECK-CONFIDENTIAL"]:
        is_model_provider = True
        if not check_sign_gpu(mmio_memory, hypervisor_socket, is_model_provider):
            return
    else:
        is_model_provider = False
        if not check_sign_gpu(mmio_memory, hypervisor_socket, is_model_provider):
            return

    match command_parsed:
        case "RESET":
            reset()
            message = b"GPU-RESET"
        case "RESET-KEYS":
            reset_keys()
            message = b"KEYS-RESET:" + command.split(b':', 1)[1]
        case "QUEUE-START":
            queue_start()
            message = b"QUEUE-WAIT"
        case "CONFIDENTIAL-ON":
            set_confidential(command)
            message = b"CONFIDENTIAL-SET:" + confidential_nonce
        case "CHECK-CONFIDENTIAL":
            message = check_if_confidential()
        case "WAIT-FOR-MODEL":
            message = wait_for_model()
        case "QUEUE-STOP":
            message = queue_stop()
        case "EXEC-START":
            message = start_exec()
        case "EXEC-CHECK":
            message = check_if_exec_done()
        case "EXEC-RUN":
            message = check_if_exec_running()
        case "QUEUE":
            message = add_op(command)
        case "LOAD":
            message = load_model(command)
        case "PAUSE":
            message = pause_exec()
        case "CLEAR":
            message = clear_model()
        case "RESUME":
            message = resume_exec()
        case "TOKEN-COUNT":
            message = check_token_count()
        case _:
            print(f"Unknown command {command_parsed}")
            message = b"UNKNOWN"

    send_mmio(hypervisor_socket, message, is_model_provider)
    mmio_memory = None

def start_gpu():
    helper.remove_file("keys/private_guest.pem")
    helper.remove_file("keys/public_guest.pem")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hypervisor_address = ('localhost', GPU_SOCKET)
    helper.connect(client_socket,hypervisor_address)

    threading.Thread(target=gpu_loop, args=(client_socket,)).start()
    
    try:
        while 1:
            mmio = client_socket.recv(1024)
            gpu_mmio(mmio, client_socket)
    finally:
        client_socket.close()

if __name__ == "__main__":
    start_gpu()