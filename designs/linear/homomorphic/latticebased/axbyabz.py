#bixr + aiyr + zr       32 64 32      128 32      160         64 + 64 + 96 = 224
#                       (224 / 32) + 1
from math import log

from crypto.utilities import random_integer, modular_inverse

SECURITY_LEVEL = 32

def generate_parameter_sizes(security_level=SECURITY_LEVEL):
    inverse_size = security_level
    x_size = (security_level * 2) - 1
    z_size = security_level * 3
        
    q_size = (security_level * 5) + 1
    r_size = security_level
    public_key_size = (q_size / r_size) + 1
    
    z_shift = (security_level * 4 * 8) + int(log(public_key_size, 2))   
    mask = (2 ** (r_size * 8)) - 1
    return inverse_size, x_size, z_size, z_shift, r_size, public_key_size, q_size, mask
    
INVERSE_SIZE, X_SIZE, Z_SIZE, Z_SHIFT, R_SIZE, PUBLIC_KEY_SIZE, Q_SIZE, MASK = generate_parameter_sizes(SECURITY_LEVEL)
    
def find_q(q_size):
    from crypto.utilities import is_prime
    q_size *= 8
    q = 2 ** q_size
    offset = 1
    while not is_prime(q + offset):
        offset += 2
    return q, offset

#q, offset = find_q(Q_SIZE)    
#print offset
#Q = q + offset
Q = (2 ** (Q_SIZE * 8)) + 1813

def generate_private_key(inverse_size=INVERSE_SIZE, q=Q):
    ai = random_integer(inverse_size)
    bi = random_integer(inverse_size)
    d = (ai * bi) % q
    return ai, bi, d
    
def generate_public_key(private_key, x_size=X_SIZE, z_size=Z_SIZE, z_shift=Z_SHIFT, 
                        public_key_size=PUBLIC_KEY_SIZE, q=Q):
    ai, bi, d = private_key
    a = modular_inverse(ai, q)
    b = modular_inverse(bi, q)
    ab = (a * b) % q
    
    public_key = []
    payload_bits = 1 << z_shift
    for element_number in range(public_key_size):
        x = random_integer(x_size)
        y = random_integer(x_size)
        z = payload_bits | random_integer(z_size)
        element = ((a * x) + (b * y) + (ab * z)) % q
        public_key.append(element)
    return public_key
    
def generate_keypair(inverse_size=INVERSE_SIZE, x_size=X_SIZE, z_size=Z_SIZE, z_shift=Z_SHIFT,
                     public_key_size=PUBLIC_KEY_SIZE, q=Q):
    private_key = generate_private_key(inverse_size, q)
    public_key = generate_public_key(private_key, x_size, z_size, z_shift, public_key_size, q)
    return public_key, private_key
    
def public_key_operation(m, public_key, r_size=R_SIZE, q=Q, mask=MASK):
    ciphertext = 0
    r_sum = 0
    for element in public_key[:-1]:
        r = random_integer(r_size)
        r_sum += r
        ciphertext += element * r
        
    # r + r_sum = m
    # m - r_sum = r    
    r = (m - r_sum) & mask
    r_sum = (r_sum + r) & mask
    assert r_sum == m
    ciphertext += public_key[-1] * r
    ciphertext %= q    
    return ciphertext 
    
def private_key_operation(ciphertext, private_key, z_shift=Z_SHIFT, q=Q, mask=MASK):
    ai, bi, d = private_key
    return (((d * ciphertext) % q) >> z_shift) & mask
    
def exchange_key(public_key, r_size=R_SIZE, q=Q):
    secret = random_integer(r_size)
    ciphertext = public_key_operation(secret, public_key, r_size, q)
    return ciphertext, secret
    
def recover_key(ciphertext, private_key, z_shift=Z_SHIFT, q=Q, mask=MASK):
    return private_key_operation(ciphertext, private_key, z_shift, q, mask)
    
def test_public_key_operation_private_key_operation():
    from unittesting import test_key_exchange
    test_key_exchange("axbyabz", generate_keypair, exchange_key, recover_key, iterations=10000)
    
if __name__ == "__main__":
    test_public_key_operation_private_key_operation()
    