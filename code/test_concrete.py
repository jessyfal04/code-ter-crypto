from concrete import fhe
import numpy as np

# Step 1: Define the function to add two numbers
def add(x, y):
    return x + y

# Step 2: Set up the compiler with encrypted input specifications
compiler = fhe.Compiler(add, {"x": "encrypted", "y": "encrypted"})

# Step 3: Define an input set for configuration
inputset = [(i, j) for i in range(10) for j in range(10)]

# Compile the function
circuit = compiler.compile(inputset)

# Step 4: Generate the necessary keys
client_key = circuit.keygen()

# Access the evaluation keys
evaluation_keys = client_key.get_evaluation_key()

# Step 5: Encrypt the input values
x = 5
y = 7
encrypted_x_y = circuit.encrypt(x, y)

# Step 6: Evaluate the function on encrypted inputs
encrypted_result = circuit.run(encrypted_x_y)

# Step 7: Decrypt the result
result = circuit.decrypt(encrypted_result)

print(f"The sum of {x} and {y} is: {result}")
