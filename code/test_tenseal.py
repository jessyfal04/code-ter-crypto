import tenseal as ts

# Setup TenSEAL context
client_context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=4096, # key length
          )
client_context.generate_galois_keys()
client_context.global_scale = 2**40

server_context = client_context.copy()
server_context.make_context_public()
server_context = server_context.serialize() # to send to server

ctx = ts.context_from(context)
enc_x = ts.ckks_vector_from(ctx, ckks_vector)
try:
    _ = ctx.galois_keys()
except:
    raise InvalidContext("the context doesn't hold galois keys")

v1 = [0, 1, 2, 3, 4]
v2 = [4, 3, 2, 1, 0]

# encrypted vectors
enc_v1 = ts.ckks_vector(client_context, v1)
enc_v2 = ts.ckks_vector(client_context, v2)

result = enc_v1 + enc_v2
result.decrypt() # ~ [4, 4, 4, 4, 4]

matrix = [
  [73, 0.5, 8],
  [81, -5, 66],
  [-100, -78, -2],
  [0, 9, 17],
  [69, 11 , 10],
]
result = enc_v1.matmul(matrix)
result.decrypt() # ~ [157, -90, 153]