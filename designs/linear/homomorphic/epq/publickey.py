from crypto.utilities import random_integer

import secretkey

Q = secretkey.Q
R_SIZE = secretkey.SECURITY_LEVEL

def generate_private_key(inverse_size=secretkey.INVERSE_SIZE, q=Q, generate_secret_key=secretkey.generate_secret_key):
    return generate_secret_key(inverse_size, q)
    
def generate_public_key(private_key, q=Q, encrypt=secretkey.encrypt, parameters=secretkey.ENCRYPTION_PARAMETERS):
    s_size, s_shift, e_size = parameters
    public_key = (encrypt(0, private_key, s_size, s_shift, e_size, q),
                  encrypt(1, private_key, s_size, s_shift, e_size, q))
    return public_key
    
def generate_keypair(inverse_size=secretkey.INVERSE_SIZE, q=Q, encrypt=secretkey.encrypt, parameters=secretkey.ENCRYPTION_PARAMETERS):
    private_key = generate_private_key(inverse_size, q)
    public_key = generate_public_key(private_key, q, encrypt, parameters)
    return public_key, private_key
    
def encrypt(m, public_key, r_size=R_SIZE, q=Q):
    x, y = public_key
    r = random_integer(r_size)
    ciphertext = ((x * r) + (y * m)) % q
    return ciphertext
    
def decrypt(ciphertext, private_key, s_mask=secretkey.S_MASK, q=Q):
    return secretkey.decrypt(ciphertext, private_key, s_mask, q)
    
def test_encrypt_decrypt():
    from unittesting import test_asymmetric_encrypt_decrypt
    test_asymmetric_encrypt_decrypt("publickey", generate_keypair, encrypt, decrypt, iterations=10000)
    
if __name__ == "__main__":
    test_encrypt_decrypt()
    