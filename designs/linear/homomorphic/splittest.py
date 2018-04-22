from crypto.utilities import random_integer, modular_inverse, big_prime, secret_split

SECURITY_LEVEL = 16
Q = big_prime(SECURITY_LEVEL + 1) # *should* be the biggest 256-bit prime, or smallest 257 bit prime

def generate_private_key(security_level=SECURITY_LEVEL, q=Q):
    encryption_key = (random_integer(security_level), random_integer(security_level))
    decryption_key = [modular_inverse(item, q) for item in encryption_key]    
    return encryption_key, decryption_key
    
def generate_public_key(private_key, security_level=SECURITY_LEVEL, q=Q):
    return (secret_key_encrypt(1, private_key, security_level, q),
            secret_key_encrypt(1, private_key, security_level, q))
            
def generate_keypair(security_level=SECURITY_LEVEL, q=Q):
    private_key = generate_private_key(security_level)
    public_key = generate_public_key(private_key[0])
    return public_key, private_key[1]
    
def secret_key_encrypt(m, key, security_level=SECURITY_LEVEL, q=Q):
    x, y = secret_split(m, security_level, 2, q)
    a, b = key
    return (a * x) % q, (b * y) % q
    
def secret_key_decrypt(ciphertext, key, q=Q):
    return sum(key[index] * ciphertext[index] for index in range(len(key))) % q
    
def add(c1, c2, q=Q):
    return [(c1[index] + c2[index]) % q for index in range(len(c1))]
    
def scalar_multiplication(c1, r, q=Q):
    return [(item * r) % q for item in c1]
    
def public_key_operation(m, public_key, security_level=SECURITY_LEVEL, q=Q):
    x, y = secret_split(m, security_level, 2, q)
    a, b = public_key
    
    return add(scalar_multiplication(a, x, q),
               scalar_multiplication(b, y, q), q)
    
def private_key_operation(ciphertext, private_key, q=Q):
    return secret_key_decrypt(ciphertext, private_key, q)
    
def encrypt(m, public_key, security_level=SECURITY_LEVEL, q=Q):
    return public_key_operation(m, public_key, security_level, q)
    
def decrypt(ciphertext, private_key, q=Q):
    return private_key_operation(ciphertext, private_key, q)
    
def test_encrypt_decrypt():
    from crypto.designs.linear.homomorphic.latticebased.unittesting import test_asymmetric_encrypt_decrypt
    test_asymmetric_encrypt_decrypt("split test", generate_keypair, encrypt, decrypt, iterations=10000, plaintext_size=SECURITY_LEVEL)
    
if __name__ == "__main__":
    test_encrypt_decrypt()
    
    