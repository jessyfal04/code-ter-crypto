import socket
import random
import argparse
from phe import paillier
from benchmark import profile_and_monitor

# Configuration
MESSAGE_SIZE = 2**4
MESSAGE_NB = 2**8
KEY_LENGTH = 2**12
SCALAR = 5
PORT = 12345  # Port for communication
BUFFER_SIZE = 4096  # Buffer size for message transfer

def generate_keypair():
    print("> Generating Keypair")
    public_key, private_key = paillier.generate_paillier_keypair(n_length=KEY_LENGTH)
    return public_key, private_key

def encrypt_messages(public_key, messages):
    print("> Encrypting Messages")
    return [public_key.encrypt(message) for message in messages]

def decrypt_messages(private_key, encrypted_messages):
    print("> Decrypting Messages")
    return [private_key.decrypt(message) for message in encrypted_messages]

def send_data(sock, data):
    sock.sendall(data.encode('utf-8'))

def receive_data(sock):
    return sock.recv(BUFFER_SIZE).decode('utf-8')

@profile_and_monitor
def client(server_ip):
    messages = [random.getrandbits(MESSAGE_SIZE) for _ in range(MESSAGE_NB)]
    public_key, private_key = generate_keypair()
    encrypted_messages = encrypt_messages(public_key, messages)
    
    # Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, PORT))
    print("> Sending Public Key to Server")
    send_data(sock, str(public_key.n))
    
    print("> Sending Encrypted Messages")
    for enc_msg in encrypted_messages:
        send_data(sock, str(enc_msg.ciphertext()))
    sock.close()

@profile_and_monitor
def server():
    # Create socket server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", PORT))
    sock.listen(1)
    print("Waiting for client connection...")
    
    conn, _ = sock.accept()
    print("> Receiving Public Key")
    public_key_n = int(receive_data(conn))
    public_key = paillier.PaillierPublicKey(n=public_key_n)
    
    encrypted_messages = []
    print("> Receiving Encrypted Messages")
    for _ in range(MESSAGE_NB):
        enc_msg = int(receive_data(conn))
        encrypted_messages.append(paillier.EncryptedNumber(public_key, enc_msg))
    
    print("> Performing Homomorphic Operations")
    encrypted_result_add_scalar = [msg + SCALAR for msg in encrypted_messages]
    encrypted_result_mul_scalar = [msg * SCALAR for msg in encrypted_messages]
    
    conn.close()
    sock.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action='store_true', help="Run as server")
    parser.add_argument("--client", type=str, help="Run as client, specify server IP")
    args = parser.parse_args()
    
    if args.server:
        server()
    elif args.client:
        client(args.client)
    else:
        print("Specify either --server or --client <server_ip>")
