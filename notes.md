tenseal 
- Garder trace de 
    - Coefficient modulus sizes [coeff_mod_bit_sizes: The coefficient modulus sizes, here [60, 40, 40, 60]. This means that the coefficient modulus will contain 4 primes of 60 bits, 40 bits, 40 bits, and 60 bits.]	
    - Saved keys
    - Context serialized size

- Saved keys : ??? all / Secret key / Galois keys / Relin keys

- Context serialized size, new metrics ??

- Polynomial modulus : 4096 / 8192
- Scheme Type : ckks / bfv
- Encryption Type : Always asymmetric

Concrete
- These parameters allow you to generate the right key set, including both secret keys and evaluation keys. Secret keys have the capability of decrypting ciphertexts, and thus should only be accessible to parties doing decryption. Evaluation keys are public material that can be sent to a server in order to run an encrypted computation.

--
insister sur scenario avec 2 vm
insister sur ram cpu et tt, pas que durée

--
Retrait "données médicales"

Benchmark :: 
- add c2p et add c2c
- diff protocoles avec même opérations 
- taille de clé avec ckks et bfv

erreur possible avec ckks mais offre flottants, difficile et global scale bloquant plus rapidement quand on fait plusieurs multiplications

nouvel article à citer sur les erruer global scales ckks