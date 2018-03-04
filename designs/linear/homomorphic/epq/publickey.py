# log(x) + log(y) + log(z) + ... >= log(q) + (2 * 256)
# 256      256        256            1792  + 512
from crypto.utilities import random_integer, modular_subtraction

import secretkey

Q = secretkey.Q
R_SIZE = secretkey.SECURITY_LEVEL
DIMENSIONS = 9

def generate_private_key(inverse_size=secretkey.INVERSE_SIZE, q=Q, generate_secret_key=secretkey.generate_secret_key):
    return generate_secret_key(inverse_size, q)
    
def generate_public_key(private_key, q=Q, encrypt=secretkey.encrypt, parameters=secretkey.ENCRYPTION_PARAMETERS, dimensions=DIMENSIONS):
    s_size, s_shift, e_size = parameters
    public_key = []
    assert dimensions > 1
    for dimension in range(dimensions):
        encryption_of_1 = encrypt(1, private_key, s_size, s_shift, e_size, q)
        public_key.append(encryption_of_1)    
    return public_key
    
def generate_keypair(inverse_size=secretkey.INVERSE_SIZE, q=Q, encrypt=secretkey.encrypt, parameters=secretkey.ENCRYPTION_PARAMETERS):
    private_key = generate_private_key(inverse_size, q)
    public_key = generate_public_key(private_key, q, encrypt, parameters)
    return public_key, private_key
    
def encrypt(m, public_key, r_size=R_SIZE, q=Q, s_mask=secretkey.S_MASK + 1):
    ciphertext = 0
    running_total = 0
    for encryption_of_1 in public_key[:-1]:
        r = random_integer(r_size)
        ciphertext += encryption_of_1 * r
        running_total += r
        
    encryption_of_1 = public_key[-1]
    correction_factor = modular_subtraction(m, running_total, s_mask) # ensures r + r + r + ... == m # + 1 because it's a mask and not the modulus
    ciphertext += encryption_of_1 * correction_factor
    ciphertext += random_integer(160)
    ciphertext %= q
    #running_total += correction_factor
    #running_total &= s_mask
    #assert running_total == m, (running_total, m)
    return ciphertext
    
def decrypt(ciphertext, private_key, s_mask=secretkey.S_MASK, q=Q):
    return secretkey.decrypt(ciphertext, private_key, s_mask, q)
    
def test_encrypt_decrypt():
    from unittesting import test_asymmetric_encrypt_decrypt
    test_asymmetric_encrypt_decrypt("publickey", generate_keypair, encrypt, decrypt, iterations=10000)
    
if __name__ == "__main__":
    test_encrypt_decrypt()
    