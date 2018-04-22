#k1a, k2b
#k1c, k2d
#k1(a + c), k2(b + d)
#
#a + c + b + d = m1 + m2
#
#
#(a + b) * (c + d)
#ac + ad + bc + bd
#
#
#k1a, k2b
#k1c, k2d
#k1k1ac + k1k2ad, k1k2bc + k2k2bd
#
#
#k1k1ac, k1k2ad, k1k2bc, k2k2bd
#k1^2, k1k2, k1k2, k2^2
from crypto.utilities import random_integer, modular_inverse, big_prime, secret_split

SECURITY_LEVEL = 32
Q = big_prime(SECURITY_LEVEL + 1) # *should* be the biggest 256-bit prime, or smallest 257 bit prime

def generate_key(security_level=SECURITY_LEVEL):
    return (random_integer(security_level), random_integer(security_level))
    
def encrypt(m, key, security_level=SECURITY_LEVEL, q=Q):
    x, y = secret_split(m, security_level, 2, q)
    a, b = key
    return (a * x) % q, (b * y) % q
    
def decrypt(ciphertext, key, q=Q):
    output = 0
    for index in range(len(key)):
        output += (modular_inverse(key[index], q) * ciphertext[index]) % q
    return output % q
    
def add(c1, c2, q=Q):
    return [(c1[index] + c2[index]) % q for index in range(len(c1))]
    
def multiply(c1, c2, q=Q):
    # (a + b) * (c + d)
    # ac + ad + bc + bd   
    #k1k1ac + k1k2ad + k2k1bc + k2k2bd    
    output = []
    for item in c1:
        for item2 in c2:
            output.append((item * item2) % q)
    return output
    
def level_key(key, depth, q=Q):
    output = multiply(key, q)
    return output
        
def test_encrypt_decrypt():
    key = generate_key()
    m0 = 0
    m1 = 1
    m2 = random_integer(SECURITY_LEVEL)
    
    c0 = encrypt(m0, key)
    c1 = encrypt(m1, key)
    c2 = encrypt(m2, key)
    
    p0 = decrypt(c0, key)
    p1 = decrypt(c1, key)
    p2 = decrypt(c2, key)
    
    assert p0 == m0
    assert p1 == m1
    assert p2 == m2
    
    m3 = m1 + m2
    c3 = add(c1, c2)
    p3 = decrypt(c3, key)
    assert p3 == m3
    
    m4 = (m2 * m2) % Q
    c4 = multiply(c2, c2)
    key2 = level_key(key, 1)
    p4 = decrypt(c4, key2)
    assert p4 == m4
    print("Unit test passed")
    
if __name__ == "__main__":
    test_encrypt_decrypt()
    