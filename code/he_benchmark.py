import socket
import random
import argparse
import json
import struct
import time
from colorama import Fore
import itertools
from abc import ABC, abstractmethod
import base64
import os

#NOTE HE LIBRARY
from phe import paillier
import tenseal as ts
from concrete import fhe

#NOTE BENCHMARK LIBRARY
import benchmark
from benchmark import profile_and_monitor

#NOTE CONSTANTS
BUFFER_SIZE = 4096
OPERATIONS_POSSIBLE = ["add_scalar", "add_encrypted", "mul_scalar", "mul_encrypted"]
DATA_RANGE = 2**7
MINI_DATA_RANGE = 2**4

def reset_benchmark():
    benchmark.current_network_bytes_sent = 0
    benchmark.current_network_bytes_received = 0
    benchmark.current_network_latency = 0
    benchmark.encrypt_start_time = 0
    benchmark.encrypt_end_time = 0
    benchmark.operation_start_time = 0
    benchmark.operation_end_time = 0
    benchmark.decrypt_start_time = 0
    benchmark.decrypt_end_time = 0

#SECTION - HE SCHEMES
class HEScheme(ABC):
    """Abstract base class for homomorphic encryption schemes"""
    
    @abstractmethod
    def generate_contexts(self, key_length, operation=None):
        """Generate public and private contexts for the scheme"""
        pass
    
    @abstractmethod
    def encrypt(self, public_context, private_context, message, message2=None):
        """Encrypt a message"""
        pass
    
    @abstractmethod
    def decrypt(self, private_context, encrypted_message):
        """Decrypt an encrypted message"""
        pass
    
    @abstractmethod
    def serialize_encrypted(self, encrypted_number_list):
        """Serialize encrypted data"""
        pass
    
    @abstractmethod
    def deserialize_encrypted(self, serialized_data, public_context):
        """Deserialize encrypted data"""
        pass
    
    @abstractmethod
    def add_scalar(self, enc, scalar):
        """Add a scalar to an encrypted number"""
        pass
    
    @abstractmethod
    def add_encrypted(self, enc1, enc2):
        """Add two encrypted numbers"""
        pass
    
    @abstractmethod
    def multiply_scalar(self, enc, scalar):
        """Multiply an encrypted number by a scalar"""
        pass

    @abstractmethod
    def multiply_encrypted(self, enc1, enc2):
        """Multiply two encrypted numbers"""
        pass
    
    @abstractmethod
    def serialize_public_context(self, public_context):
        """Serialize public context"""
        pass
    
    @abstractmethod
    def deserialize_public_context(self, serialized_context):
        """Deserialize public context"""
        pass

class PaillierScheme(HEScheme):
    """Paillier homomorphic encryption scheme implementation"""
    
    def generate_contexts(self, key_length, operation=None):
        """Generate a Paillier keypair with optimized parameters"""
        print(f"> Generating Keypair of length {key_length} bits")
        return paillier.generate_paillier_keypair(n_length=key_length)
    
    def encrypt(self, public_context, private_context, message, message2=None):
        """Encrypt a message using Paillier"""
        return public_context.encrypt(message)
    
    def decrypt(self, private_context, encrypted_message):
        """Decrypt an encrypted message using Paillier"""
        return private_context.decrypt(encrypted_message)
    
    def serialize_encrypted(self, encrypted_number_list):
        """Serialize encrypted data for Paillier"""
        print("> Serializing encrypted data")
        enc_dict = {
            'values': [
                (str(x.ciphertext()), x.exponent) for x in encrypted_number_list
            ]
        }
        return json.dumps(enc_dict)
    
    def deserialize_encrypted(self, serialized_data, public_context):
        """Deserialize encrypted data for Paillier"""
        print("> Deserializing encrypted data")
        data_dict = json.loads(serialized_data)
        return [
            paillier.EncryptedNumber(public_context, int(ctxt), int(exp))
            for (ctxt, exp) in data_dict['values']
        ]
    
    def add_scalar(self, enc, scalar):
        """Add a scalar to an encrypted number using Paillier"""
        return enc + scalar
    
    def add_encrypted(self, enc1, enc2):
        """Add two encrypted numbers using Paillier"""
        return enc1 + enc2
    
    def multiply_scalar(self, enc, scalar):
        """Multiply an encrypted number by a scalar using Paillier"""
        return enc * scalar
    
    def multiply_encrypted(self, enc1, enc2):
        """Multiply two encrypted numbers using Paillier"""
        raise NotImplementedError("Paillier does not support multiplication of encrypted numbers")
    
    def serialize_public_context(self, public_context):
        """Serialize Paillier public key"""
        return {'public_key': {'g': public_context.g, 'n': public_context.n}}
    
    def deserialize_public_context(self, serialized_context):
        """Deserialize Paillier public key"""
        public_context_dict = json.loads(serialized_context)['public_key']
        return paillier.PaillierPublicKey(n=int(public_context_dict['n']))

class BFVScheme(HEScheme):
    """BFV homomorphic encryption scheme implementation using TenSEAL"""
    
    def generate_contexts(self, key_length, operation=None):
        """Generate a BFV keypair with optimized parameters"""
        print(f"> Generating Keypair of length {key_length} bits")
        context = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=key_length, plain_modulus=1032193)
        context.generate_galois_keys()
        private_context = context.secret_key()
        context.make_context_public()
        return context, private_context
    
    def encrypt(self, public_context, private_context, message, message2=None):
        """Encrypt a message using BFV"""
        if isinstance(message, list):
            return ts.bfv_vector(public_context, message)
        else:
            return ts.bfv_vector(public_context, [message])
    
    def decrypt(self, private_context, encrypted_message):
        """Decrypt an encrypted message using BFV"""
        return encrypted_message.decrypt(private_context)
    
    def serialize_encrypted(self, encrypted_number_list):
        """Serialize encrypted data for BFV"""
        print("> Serializing encrypted data")
        # Serialize each encrypted vector and convert to base64
        serialized_list = []
        for enc in encrypted_number_list:
            serialized = enc.serialize()
            serialized_list.append(base64.b64encode(serialized).decode('utf-8'))
        return json.dumps(serialized_list)
    
    def deserialize_encrypted(self, serialized_data, public_context):
        """Deserialize encrypted data for BFV"""
        print("> Deserializing encrypted data")
        # Deserialize each encrypted vector from base64
        serialized_list = json.loads(serialized_data)
        return [ts.bfv_vector_from(public_context, base64.b64decode(serialized)) for serialized in serialized_list]
    
    def add_scalar(self, enc, scalar):
        """Add a scalar to an encrypted number using BFV"""
        return enc + scalar
    
    def add_encrypted(self, enc1, enc2):
        """Add two encrypted numbers using BFV"""
        return enc1 + enc2
    
    def multiply_scalar(self, enc, scalar):
        """Multiply an encrypted number by a scalar using BFV"""
        return enc * scalar
    
    def multiply_encrypted(self, enc1, enc2):
        """Multiply two encrypted numbers using BFV"""
        return enc1 * enc2
    
    def serialize_public_context(self, public_context):
        """Serialize BFV public context"""
        serialized = public_context.serialize()
        return base64.b64encode(serialized).decode('utf-8')
    
    def deserialize_public_context(self, serialized_context):
        """Deserialize BFV public context"""
        serialized_bytes = base64.b64decode(serialized_context)
        return ts.context_from(serialized_bytes)

class CKKSScheme(HEScheme):
    """CKKS homomorphic encryption scheme implementation using TenSEAL"""
    
    def generate_contexts(self, key_length, operation=None):
        """Generate a CKKS keypair with optimized parameters"""
        print(f"> Generating Keypair of length {key_length} bits")
        # Create context with proper parameters
        context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=key_length,
            coeff_mod_bit_sizes=[30, 20, 20, 30] * int(key_length/4096) # Set the appropriate coeff_mod_bit_sizes
        )
        context.global_scale = pow(2, 20 * int(key_length/4096))  # Set appropriate scale for CKKS
        context.generate_galois_keys()
        private_context = context.secret_key()
        context.make_context_public()
        return context, private_context
    
    def encrypt(self, public_context, private_context, message, message2=None):
        """Encrypt a message using CKKS"""
        if isinstance(message, list):
            return ts.ckks_vector(public_context, message)
        else:
            return ts.ckks_vector(public_context, [message])
    
    def decrypt(self, private_context, encrypted_message):
        """Decrypt an encrypted message using CKKS"""
        return encrypted_message.decrypt(private_context)
    
    def serialize_encrypted(self, encrypted_number_list):
        """Serialize encrypted data for CKKS"""
        print("> Serializing encrypted data")
        # Serialize each encrypted vector and convert to base64
        serialized_list = []
        for enc in encrypted_number_list:
            serialized = enc.serialize()
            serialized_list.append(base64.b64encode(serialized).decode('utf-8'))
        return json.dumps(serialized_list)
    
    def deserialize_encrypted(self, serialized_data, public_context):
        """Deserialize encrypted data for CKKS"""
        print("> Deserializing encrypted data")
        # Deserialize each encrypted vector from base64
        serialized_list = json.loads(serialized_data)
        return [ts.ckks_vector_from(public_context, base64.b64decode(serialized)) for serialized in serialized_list]
    
    def add_scalar(self, enc, scalar):
        """Add a scalar to an encrypted number using CKKS"""
        return enc + scalar
    
    def add_encrypted(self, enc1, enc2):
        """Add two encrypted numbers using CKKS"""
        return enc1 + enc2
    
    def multiply_scalar(self, enc, scalar):
        """Multiply an encrypted number by a scalar using CKKS"""
        result = enc * scalar
        return result
    
    def multiply_encrypted(self, enc1, enc2):
        """Multiply two encrypted numbers using CKKS"""
        result = enc1 * enc2
        return result
    
    def serialize_public_context(self, public_context):
        """Serialize CKKS public context"""
        serialized = public_context.serialize()
        return base64.b64encode(serialized).decode('utf-8')
    
    def deserialize_public_context(self, serialized_context):
        """Deserialize CKKS public context"""
        serialized_bytes = base64.b64decode(serialized_context)
        return ts.context_from(serialized_bytes)

class TFHEScheme(HEScheme):
    """TFHE homomorphic encryption scheme implementation using Concrete"""
    
    def generate_contexts(self, key_length, operation=None):
        """Generate TFHE circuit and keys"""
        print(f"> Generating TFHE circuit for operation {operation}")
        
        # Define the function to compile based on operation
        if operation == "add_encrypted":
            def functionToCompile(x, y):
                return x + y
            input_types = {"x": "encrypted", "y": "encrypted"}
        elif operation == 'add_scalar':
            def functionToCompile(x, s):
                return x + s
            input_types = {"x": "encrypted", "s": "clear"}
        elif operation == 'mul_encrypted':
            def functionToCompile(x, y):
                return x * y
            input_types = {"x": "encrypted", "y": "encrypted"}
        elif operation == 'mul_scalar':
            def functionToCompile(x, s):
                return x * s
            input_types = {"x": "encrypted", "s": "clear"}
        else:
            raise ValueError(f"Unsupported operation: {operation}")
        
        # Compile the circuit with uint5 range (0-31)
        compiler = fhe.Compiler(functionToCompile, input_types)
        if operation == "mul_encrypted":
            inputset = [(i, j) for i in range(MINI_DATA_RANGE) for j in range(MINI_DATA_RANGE)]
        else:
            inputset = [(i, j) for i in range(DATA_RANGE) for j in range(DATA_RANGE)]
        circuit = compiler.compile(inputset)
        circuit.keygen()
        
        # Generate contexts
        private_context = {"circuit_client": circuit.client}
        public_context = {
            "circuit_server": circuit.server,
            "evaluation_keys": circuit.client.evaluation_keys
        }
        
        return public_context, private_context
    
    def encrypt(self, public_context, private_context, message, message2=None):
        """Encrypt a message using TFHE"""
        if message2 is None:
            message2 = message
        return [
            private_context["circuit_client"].encrypt(d1, d2)
            for d1, d2 in zip(message, message2)
        ]
    
    def decrypt(self, private_context, encrypted_message):
        """Decrypt an encrypted message using TFHE"""
        return private_context["circuit_client"].decrypt(encrypted_message)
    
    def serialize_encrypted(self, encrypted_data):
        """Serialize encrypted data for TFHE"""
        print("> Serializing encrypted data")
        # Handle lists of encrypted data
        if isinstance(encrypted_data, list):
            serialized_list = []
            for item in encrypted_data:
                if isinstance(item, tuple):
                    # Handle tuple of encrypted values
                    serialized_tuple = [base64.b64encode(ei.serialize()).decode('utf-8') for ei in item]
                    serialized_list.append(serialized_tuple)
                else:
                    # Handle single Value object
                    serialized = base64.b64encode(item.serialize()).decode('utf-8')
                    serialized_list.append(serialized)
            return json.dumps(serialized_list)
        elif isinstance(encrypted_data, tuple):
            # Handle single tuple of encrypted values
            serialized_tuple = [base64.b64encode(ei.serialize()).decode('utf-8') for ei in encrypted_data]
            return json.dumps(serialized_tuple)
        else:
            # Handle single Value object
            serialized = base64.b64encode(encrypted_data.serialize()).decode('utf-8')
            return json.dumps(serialized)
    
    def deserialize_encrypted(self, serialized_data, public_context):
        """Deserialize encrypted data for TFHE"""
        print("> Deserializing encrypted data")
        # Parse the JSON data
        data = json.loads(serialized_data)
        
        # Handle different data structures
        if isinstance(data, list):
            deserialized_list = []
            for item in data:
                if isinstance(item, list):
                    # Handle list of base64 strings (from tuple serialization)
                    deserialized_tuple = tuple([
                        fhe.Value.deserialize(base64.b64decode(ei))
                        for ei in item
                    ])
                    deserialized_list.append(deserialized_tuple)
                else:
                    # Handle single base64 string
                    deserialized_list.append(
                        fhe.Value.deserialize(base64.b64decode(item))
                    )
            return deserialized_list
        else:
            # Handle single base64 string
            return fhe.Value.deserialize(base64.b64decode(data))
    
    def add_scalar(self, enc, scalar):
        """Add a scalar to an encrypted number using TFHE"""
        raise NotImplementedError("This operation is handled by the circuit")
    
    def add_encrypted(self, enc1, enc2):
        """Add two encrypted numbers using TFHE"""
        # This operation is handled by the circuit
        raise NotImplementedError("This operation is handled by the circuit")
    
    def multiply_scalar(self, enc, scalar):
        """Multiply an encrypted number by a scalar using TFHE"""
        # This operation is handled by the circuit
        raise NotImplementedError("This operation is handled by the circuit")
    
    def multiply_encrypted(self, enc1, enc2):
        """Multiply two encrypted numbers using TFHE"""
        # This operation is handled by the circuit
        raise NotImplementedError("This operation is handled by the circuit")
    
    def serialize_public_context(self, public_context):
        """Serialize TFHE public context"""
        # Save server circuit to file
        public_context["circuit_server"].save("server.zip")
        with open("server.zip", "rb") as f:
            circuit_server_bytes = base64.b64encode(f.read()).decode('utf-8')
        os.remove("server.zip")
        
        # Serialize evaluation keys to base64
        evaluation_keys_bytes = public_context["evaluation_keys"].serialize()
        evaluation_keys_base64 = base64.b64encode(evaluation_keys_bytes).decode('utf-8')
        
        return {
            "circuit_server": circuit_server_bytes,
            "evaluation_keys": evaluation_keys_base64
        }
    
    def deserialize_public_context(self, serialized_context):
        """Deserialize TFHE public context"""
        # Load from json
        serialized_context = json.loads(serialized_context)
        # Load server circuit from base64
        server_circuit_bytes = base64.b64decode(serialized_context["circuit_server"])
        with open("server.zip", "wb") as f:
            f.write(server_circuit_bytes)
        
        circuit_server = fhe.Server.load("server.zip")
        os.remove("server.zip")
        
        # Deserialize evaluation keys from base64
        evaluation_keys_bytes = base64.b64decode(serialized_context["evaluation_keys"])
        evaluation_keys = fhe.EvaluationKeys.deserialize(evaluation_keys_bytes)
        
        return {
            "circuit_server": circuit_server,
            "evaluation_keys": evaluation_keys
        }

# Dictionary of available schemes
SCHEMES = {
    'paillier': PaillierScheme(),
    'bfv': BFVScheme(),
    'ckks': CKKSScheme(),
    'tfhe': TFHEScheme()
}
#!SECTION - END HE SCHEMES

#SECTION - NETWORKING
#ANCHOR - CONSTANTS
def create_socket():
    """Create and configure a socket with optimized settings"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock

#ANCHOR - SENDING 
def send_data(sock, data):
    """Send data efficiently"""
    data_bytes = data.encode('utf-8')
    data_length = len(data_bytes)
    
    sock.sendall(struct.pack('!I', data_length))
    
    sent_bytes = 0
    while sent_bytes < data_length:
        chunk = data_bytes[sent_bytes:sent_bytes + BUFFER_SIZE]
        sock.sendall(chunk)
        sent_bytes += len(chunk)
    
    benchmark.current_network_bytes_sent += data_length

#ANCHOR - RECEIVING
class EmptyResponseError(Exception):
    """Raised when no data is received from the socket"""
    pass

def receive_data(sock):
    """Receive data efficiently"""
    raw_length = sock.recv(4)
    if not raw_length:
        raise EmptyResponseError("No data received from socket")
    data_length = struct.unpack('!I', raw_length)[0]
    
    received_bytes = 0
    data_chunks = []
    while received_bytes < data_length:
        chunk = sock.recv(min(BUFFER_SIZE, data_length - received_bytes))
        if not chunk:
            raise EmptyResponseError("Connection closed while receiving data")
        data_chunks.append(chunk)
        received_bytes += len(chunk)
    
    data = b''.join(data_chunks).decode('utf-8')
    benchmark.current_network_bytes_received += received_bytes
    return data
#!SECTION - END NETWORKING

#SECTION - HOMOMORPHIC OPERATIONS
#ANCHOR - PERFORM OPERATION
def perform_homomorphic_operation(scheme, operation, data_list, scalar=None, data_list2=None, nb_operations=1, public_context=None):
    """Perform a homomorphic operation on encrypted data"""
    print(f"> Performing homomorphic operation {operation}, {nb_operations} times")
    data_list_copy = data_list.copy()
    data_list2_copy = data_list2.copy() if data_list2 is not None else None
    result = None

    # Special handling for TFHE scheme
    if isinstance(scheme, TFHEScheme):
        circuit_server = public_context["circuit_server"]
        evaluation_keys = public_context["evaluation_keys"]
        
        for _ in range(nb_operations):
            if "encrypted" in operation and operation in OPERATIONS_POSSIBLE:
                result = [
                    circuit_server.run(
                        m,
                        evaluation_keys=evaluation_keys
                    )
                    for m in data_list_copy
                ]
            elif not "encrypted" in operation and operation in OPERATIONS_POSSIBLE:
                result = [
                    circuit_server.run(
                        enc,
                        evaluation_keys=evaluation_keys
                    )
                    for enc in data_list_copy
                ]
            else:
                raise ValueError(f"Unsupported operation: {operation}")
    else:
        # Original implementation for other schemes
        for _ in range(nb_operations):
            if operation == 'add_scalar':
                result = [scheme.add_scalar(m, scalar) for m in data_list_copy]
            elif operation == 'add_encrypted':
                result = [scheme.add_encrypted(m, m2) for m, m2 in zip(data_list_copy, data_list2_copy)]
            elif operation == 'mul_scalar':
                result = [scheme.multiply_scalar(m, scalar) for m in data_list_copy]
            elif operation == 'mul_encrypted':
                result = [scheme.multiply_encrypted(m, m2) for m, m2 in zip(data_list_copy, data_list2_copy)]
            else:
                raise ValueError(f"Unsupported operation: {operation}")
    return result
#!SECTION - END HOMOMORPHIC OPERATIONS

#SECTION - KEY EXCHANGE
#ANCHOR - SEND KEY
def send_public_context(sock, scheme, public_context):
    """Send public key efficiently"""
    print("> Sending Public Key to Server")
    key_data = scheme.serialize_public_context(public_context)
    send_data(sock, json.dumps(key_data))
    
    # Wait for server completion
    print("> Waiting for server completion...")
    if receive_data(sock) != "finished":
        raise ValueError("Unexpected response from server")

#ANCHOR - RECEIVE KEY
def receive_public_context(sock, scheme):
    """Receive public key efficiently"""
    print("> Receiving Public Key from Client")
    data = receive_data(sock)
    public_context = scheme.deserialize_public_context(data)
    
    # Signal completion to client
    print("> Signaling completion to client...")
    send_data(sock, "finished")
    return public_context
#!SECTION - END KEY EXCHANGE

#SECTION - MEDICAL DATA
#ANCHOR - GENERATE DATA
def generate_data(num_elements, operation=None, scheme=None):
    """Generate data for homomorphic operations"""
    if isinstance(scheme, TFHEScheme) and operation == "mul_encrypted":
        return [random.randint(0, MINI_DATA_RANGE) for _ in range(num_elements)]
    else:
        return [random.randint(0, DATA_RANGE) for _ in range(num_elements)]
#!SECTION - END MEDICAL DATA

#SECTION - LATENCY
#ANCHOR - MEASURE CLIENT
def measure_latency_client(sock):
    """Measure network latency from client side"""
    # Check readyness of the server
    send_data(sock, "ping_ready")
    if receive_data(sock) != "pong_ready":
        raise ValueError("Unexpected response")

    # Start RTT of the client
    start_time = time.time()
    send_data(sock, "ping")
    if receive_data(sock) != "pong":
        raise ValueError("Unexpected response")
    end_time = time.time()
    
    # Store the RTT and Send the RTT to the server
    rtt_client = (end_time - start_time) * 1000
    print(f"^ RTT: {rtt_client:.2f} ms")
    benchmark.current_network_latency = rtt_client
    send_data(sock, str(rtt_client))

#ANCHOR - MEASURE SERVER
def measure_latency_server(sock):
    """Measure network latency from server side"""
    # Validate readyness of the server
    if receive_data(sock) != "ping_ready":
        raise ValueError("Unexpected response")
    send_data(sock, "pong_ready")

    # Start RTT of the client
    if receive_data(sock) != "ping":
        raise ValueError("Unexpected response")
    send_data(sock, "pong")

    # Get the RTT of client
    rtt_server = float(receive_data(sock))

    # Store the RTT
    print(f"^ RTT: {rtt_server:.2f} ms")
    benchmark.current_network_latency = rtt_server
#!SECTION - END LATENCY

#SECTION - CLIENT WORKFLOW
#ANCHOR - RUN OPERATIONS
def run_client_operations(sock, scheme, operation, public_context, private_context, config):
    """Run client operations efficiently"""
    measure_latency_client(sock)

    nb_data = config['nb_data']

    # Generate data
    data = generate_data(nb_data, operation=operation, scheme=scheme)
    scalar = 4

    # Encrypt data
    benchmark.encrypt_start_time = time.perf_counter()
    if isinstance(scheme, TFHEScheme):
        # For TFHE, we need to encrypt pairs of data together
        data2 = data if "encrypted" in operation else [scalar] * len(data)
        encrypted_data = scheme.encrypt(public_context, private_context, data, data2)
    else:
        encrypted_data = [scheme.encrypt(public_context, private_context, m) for m in data]
    print(f"> Computing {operation} on {nb_data} elements")

    # Prepare data for computation
    data_to_compute = {
        'operation': operation,
        'scalar': scalar,
        'data': scheme.serialize_encrypted(encrypted_data)
    }
    benchmark.encrypt_end_time = time.perf_counter()

    # Add second dataset for add_encrypted operation
    if "encrypted" in operation and not isinstance(scheme, TFHEScheme):
        data_to_compute['data2'] = data_to_compute['data']

    # Send data and receive result
    print("> Sending data to server for computation")
    send_data(sock, json.dumps(data_to_compute))

    print("> Waiting for server result...")
    serialized_data = receive_data(sock)

    # Process result
    benchmark.decrypt_start_time = time.perf_counter()
    encrypted_result = scheme.deserialize_encrypted(serialized_data, public_context)
    decrypted_result = [scheme.decrypt(private_context, m) for m in encrypted_result]
    benchmark.decrypt_end_time = time.perf_counter()

    # Print to verify the result
    print(Fore.CYAN)
    print(f"# data: {data[0:max(1, min(4, len(data)))]}")
    print(f"# scalar: {scalar}")
    print(f"# operation: {operation}")
    print(f"# result: {decrypted_result[0:max(1, min(4, len(decrypted_result)))]}")
    print(Fore.RESET)

    # Signal completion to server
    print("> Signaling completion to server...")
    send_data(sock, "finished")

#ANCHOR - CLIENT
def client(sock, scheme, config, public_context, private_context):
    """Client main function"""
    folder_prefix = config["folder_prefix"] if config["folder_prefix"] != "" else f"client_{config['operation']}_{config['nb_data']}bits"
    annotation_str = (
        f"Client Operation | "
        f"NB_RUNS={config['nb_runs']}, "
        f"NB_DATA={config['nb_data']}, "
        f"KEY_LENGTH={config['key_length']}, "
        f"OPERATION={config['operation']}, "
        f"SCHEME={config['scheme']}"
    )

    benchmarked_fn = profile_and_monitor(
        number=config['nb_runs'],
        folder_prefix=folder_prefix,
        annotation=annotation_str
    )(run_client_operations)

    benchmarked_fn(sock, scheme, config['operation'], public_context, private_context, config)
#!SECTION - END CLIENT WORKFLOW

#SECTION - SERVER WORKFLOW
#ANCHOR - RUN OPERATIONS
def run_server_operations(sock, scheme, config, public_context):
    """Run server operations efficiently"""
    measure_latency_server(sock)

    print("> Waiting for client data...")
    data_to_compute = json.loads(receive_data(sock))
    operation = data_to_compute['operation']
    scalar = data_to_compute['scalar']
    
    # Process input data
    data_list = scheme.deserialize_encrypted(data_to_compute['data'], public_context)
    data_list2 = scheme.deserialize_encrypted(data_to_compute['data2'], public_context) if "encrypted" in operation and not isinstance(scheme, TFHEScheme) else None

    # Perform operations
    benchmark.operation_start_time = time.perf_counter()
    result = perform_homomorphic_operation(
        scheme,
        operation, 
        data_list, 
        scalar=scalar, 
        data_list2=data_list2,
        nb_operations=config['nb_operations'],
        public_context=public_context
    )
    benchmark.operation_end_time = time.perf_counter()

    # Send result
    serialized_result = scheme.serialize_encrypted(result)
    print("> Sending computation result back to client")
    send_data(sock, serialized_result)

    # Print to verify the result
    print(Fore.CYAN)
    print(f"# result: {result[0:max(1, min(4, len(result)))]}")
    print(Fore.RESET)

    # Wait for client completion
    print("> Waiting for client completion...")
    if receive_data(sock) != "finished":
        raise ValueError("Unexpected response from client")

#ANCHOR - SERVER
def server(sock, scheme, config, public_context):
    """Server main function"""
    folder_prefix = config["folder_prefix"] if config["folder_prefix"] != "" else f"server_{config['operation']}_{config['nb_data']}bits"
    annotation_str = (
        f"Server Operation | "
        f"NB_RUNS={config['nb_runs']}, "
        f"NB_DATA={config['nb_data']}, "
        f"KEY_LENGTH={config['key_length']}, "
        f"OPERATION={config['operation']}, "
        f"SCHEME={config['scheme']}"
    )

    benchmarked_fn = profile_and_monitor(
        number=config['nb_runs'],
        folder_prefix=folder_prefix,
        annotation=annotation_str
    )(run_server_operations)

    benchmarked_fn(sock, scheme, config, public_context)
#!SECTION - END SERVER WORKFLOW

#SECTION - MAIN
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", action='store_true', help="Run as server")
    parser.add_argument("--client", type=str, help="Run as client, specify server IP")
    parser.add_argument("--port", type=int, default=12345, help="Port to use for communication (default: 12345)")
    parser.add_argument("--operation", type=str, default="all",
                        help="Operation(s): 'add', 'add_encrypted', 'mul', 'all' or comma-separated list.")
    parser.add_argument("--nb_runs", type=int, default=2, help="Number of runs for the benchmark")
    parser.add_argument("--nb_data", type=str, default="1024",
                        help="Number of data elements (integer or comma-separated list of values to test)")
    parser.add_argument("--key_length", type=str, default="4096",
                        help="Key length in bits (integer or comma-separated list of values to test)")
    parser.add_argument("--nb_operations", type=int, default=16,
                        help="Number of homomorphic operations to perform per run")
    parser.add_argument("--folder_prefix", type=str, default="", help="Folder name for results")
    parser.add_argument("--scheme", type=str, default="paillier",
                        help="Homomorphic encryption scheme(s) to use (default: paillier). Can be a comma-separated list of schemes: paillier,bfv,ckks")

    args = parser.parse_args()

    # Parse schemes
    schemes_list = (
        [x.strip() for x in args.scheme.split(',')] if ',' in args.scheme
        else [args.scheme]
    )

    # Validate schemes
    for scheme_name in schemes_list:
        if scheme_name not in SCHEMES:
            raise ValueError(f"Unsupported scheme: {scheme_name}. Available schemes: {', '.join(SCHEMES.keys())}")

    # Parse operations
    operations = args.operation.split(',') if ',' in args.operation else \
                OPERATIONS_POSSIBLE if args.operation == 'all' else [args.operation]

    # Parse number of data elements
    nb_data_list = (
        [int(x.strip()) for x in args.nb_data.split(',')] if ',' in args.nb_data
        else [int(args.nb_data)]
    )

    # Parse key lengths
    key_length_list = (
        [int(x.strip()) for x in args.key_length.split(',')] if ',' in args.key_length
        else [int(args.key_length)]
    )

    # Server mode
    if args.server:
        server_sock = create_socket()
        try:
            server_sock.bind(("0.0.0.0", args.port))
            server_sock.listen(1)
            print(f"! Server listening on port {args.port}")
            sock, addr = server_sock.accept()
            print(f"! Server accepted connection from {addr}")

            for scheme_name in schemes_list:
                scheme = SCHEMES[scheme_name]
                for key_length in key_length_list:

                    bool_contextGenerated = False
                    for operation in operations:
                        if not bool_contextGenerated or scheme_name == "tfhe":
                            public_context = receive_public_context(sock, scheme)
                            bool_contextGenerated = True

                        # Single loop for all combinations
                        for nb_data in nb_data_list:
                            
                            reset_benchmark()
                            config = {
                                'nb_runs': args.nb_runs,
                                'nb_data': nb_data,
                                'key_length': key_length,
                                'operation': operation,
                                'nb_operations': args.nb_operations,
                                'folder_prefix': args.folder_prefix,
                                'scheme': scheme_name
                            }

                            print(Fore.YELLOW)
                            print("> Configuration:")
                            for k, v in config.items():
                                print(f"  {k}: {v}")
                            print(Fore.RESET)

                            server(sock, scheme, config, public_context)

            sock.close()
        finally:
            server_sock.close()

    # Client mode
    elif args.client:
        client_sock = create_socket()
        try:
            client_sock.connect((args.client, args.port))
            print(f"! Client connected to {args.client}:{args.port}")

            for scheme_name in schemes_list:
                scheme = SCHEMES[scheme_name]
                for key_length in key_length_list:

                    bool_contextGenerated = False
                    for operation in operations:
                        if not bool_contextGenerated or scheme_name == "tfhe":
                            public_context, private_context = scheme.generate_contexts(key_length, operation=operation)
                            send_public_context(client_sock, scheme, public_context)
                            bool_contextGenerated = True

                        # Single loop for all combinations
                        for nb_data in nb_data_list:
                            
                            reset_benchmark()
                            config = {
                                'nb_runs': args.nb_runs,
                                'nb_data': nb_data,
                                'key_length': key_length,
                                'operation': operation,
                                'nb_operations': args.nb_operations,
                                'folder_prefix': args.folder_prefix,
                                'scheme': scheme_name
                            }

                            print(Fore.YELLOW)
                            print("> Configuration:")
                            for k, v in config.items():
                                print(f"  {k}: {v}")
                            print(Fore.RESET)

                            client(client_sock, scheme, config, public_context, private_context)

        finally:
            client_sock.close()

    else:
        print("Please specify either --server or --client <server_ip>. See --help.")
#!SECTION - END MAIN
