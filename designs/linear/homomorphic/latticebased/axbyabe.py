# ax + by + abe       96 32      96 96
#aibi(ax + by + abe)
#bix + aiy + e        32 32         96      96
from crypto.utilities import random_integer, modular_inverse

SECURITY_LEVEL = 32

def find_q(security_level=SECURITY_LEVEL):
    from crypto.utilities import is_prime
    q_size = security_level * 3
    offset = 1
    q = (2 ** (q_size * 8)) 
    while not is_prime(q + offset):
        offset += 2                
    return q, offset
    
#q, offset = find_q(SECURITY_LEVEL)
Q = (2 ** (SECURITY_LEVEL * 3 * 8)) + 183

def generate_parameter_sizes(security_level=SECURITY_LEVEL):
    inverse_size = security_level
    x_size = security_level
    e_size = security_level * 2
    e_shift = (security_level * 2 * 8) + 1
    return inverse_size, x_size, e_size, e_shift
    
INVERSE_SIZE, X_SIZE, E_SIZE, E_SHIFT = generate_parameter_sizes(SECURITY_LEVEL)
    
def generate_decryption_key(inverse_size=INVERSE_SIZE, q=Q):
    ai = random_integer(inverse_size)
    bi = random_integer(inverse_size)
    d = (ai * bi) % q
    return ai, bi, d
    
def generate_encryption_key(decryption_key, q=Q):
    ai, bi, d = decryption_key
    a = modular_inverse(ai, q)
    b = modular_inverse(bi, q)
    ab = (a * b) % q
    return a, b, ab
    
def generate_secret_key(inverse_size=INVERSE_SIZE, q=Q):
    decryption_key = generate_decryption_key(inverse_size, q)
    encryption_key = generate_encryption_key(decryption_key, q)
    return encryption_key, decryption_key
    
def encrypt(m, secret_key, x_size=X_SIZE, e_size=E_SIZE, e_shift=E_SHIFT, q=Q):
    encryption_key, decryption_key = secret_key
    a, b, ab = encryption_key
    x = random_integer(x_size)
    y = random_integer(x_size)
    e = random_integer(e_size)
    e |= m << e_shift
    ciphertext = ((a * x) + (b * y) + (ab * e)) % q
    return ciphertext
    
def decrypt(ciphertext, secret_key, e_shift=E_SHIFT, q=Q):
    encryption_key, decryption_key = secret_key
    ai, bi, d = decryption_key
    m = ((d * ciphertext) % q) >> e_shift
    return m
    
def test_encrypt_decrypt():
    from unittesting import test_symmetric_encrypt_decrypt    
    secret_key = generate_secret_key()
    m0 = 0
    m1 = 1
    mr = random_integer(32) >> 1
    c0 = encrypt(m0, secret_key)
    c1 = encrypt(m1, secret_key)
    cr = encrypt(mr, secret_key)
    p0 = decrypt(c0, secret_key)
    p1 = decrypt(c1, secret_key)
    pr = decrypt(cr, secret_key)
    assert p0 == m0, (p0, m0)
    assert p1 == m1, (p1, m1)
    assert pr == mr, (pr, mr)
    test_symmetric_encrypt_decrypt("axbyabe", generate_secret_key, encrypt, decrypt, iterations=10000)
    
if __name__ == "__main__":
    test_encrypt_decrypt()
    
    
    