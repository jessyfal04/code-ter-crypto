from concrete import fhe

# Define a simple addition function

def add(x, y):
    return x + y

# Create a compiler where x is encrypted and y is clear
compiler = fhe.Compiler(add, {"x": "encrypted", "y": "clear"})

# Define an inputset; these sample inputs help determine the range of values.
inputset = [(2, 3), (0, 0), (1, 6), (7, 7), (7, 1), (3, 2), (6, 1), (1, 7), (4, 5), (5, 4)]

# Compile the circuit using the provided inputset
print("Compilation...")
circuit = compiler.compile(inputset)

# Key generation (this step sets up the secret keys on the server, and in a full deployment, would be used on the client as well)
print("Key generation...")
circuit.keygen()

# Now, perform homomorphic evaluation:
# Encrypt the first argument (x) while providing y in clear
print("Homomorphic evaluation...")
encrypted_x, clear_y = circuit.client.encrypt(2, 6)

eX= encrypted_x.serialize()
eY = clear_y.serialize()

eeX = fhe.Value.deserialize(eX)
eeY = fhe.Value.deserialize(eY)

encrypted_result = circuit.server.run(eeX, eeY, evaluation_keys=circuit.client.evaluation_keys)

# Decrypt the result and print
result = circuit.decrypt(encrypted_result)

assert result == add(2, 6)
print(f"Result of add(2, 6): {result}")