#           224     32+32+96      160 + 96 = 256
#                                            224
from crypto.utilities import modular_inverse, random_integer

SECURITY_LEVEL = 32

def generate_parameter_sizes(security_level=SECURITY_LEVEL):
    from math import log
    inverse_size = security_level
    e_size = (security_level * 3) - 1
    s_size = (security_level * 5) - 1
    q_size = (security_level * 7) + 4
    qr_size = security_level * 7
    
    r_size = security_level
    dimensions = q_size / r_size
    s_shift = (security_level * 6 * 8) + int(log(dimensions, 2))
    mask = (2 ** (security_level * 8)) - 1    
    return inverse_size, e_size, s_size, q_size, r_size, dimensions, s_shift, mask, qr_size
    
INVERSE_SIZE, E_SIZE, S_SIZE, Q_SIZE, R_SIZE, DIMENSIONS, S_SHIFT, MASK, QR_SIZE = generate_parameter_sizes(SECURITY_LEVEL)

def generate_private_key(inverse_size=INVERSE_SIZE, q_size=Q_SIZE):
    while True:
        inverse = random_integer(inverse_size)
        q = random_integer(q_size)    
        try:
            modular_inverse(inverse, q)
        except ValueError:
            continue
        else:
            break
    return inverse, q
    
def generate_public_key(private_key, e_size=E_SIZE, s_size=S_SIZE, dimensions=DIMENSIONS, s_shift=S_SHIFT, qr_size=QR_SIZE):
    inverse, q = private_key
    a = modular_inverse(inverse, q)
    public_key = []
    payload_section = 1 << s_shift
    for element_number in range(dimensions):
        e = random_integer(e_size)
        s = random_integer(s_size)
        s |= payload_section
        element = (((a * s) + e) % q) + (q * random_integer(qr_size))
        public_key.append(element)
    return public_key

def generate_keypair(inverse_size=INVERSE_SIZE, e_size=E_SIZE, s_size=S_SIZE, dimensions=DIMENSIONS, q_size=Q_SIZE, s_shift=S_SHIFT, qr_size=QR_SIZE):
    private_key = generate_private_key(inverse_size, q_size)
    public_key = generate_public_key(private_key, e_size, s_size, dimensions, s_shift, qr_size)
    return public_key, private_key
    
def encapsulate_key(public_key, r_size=R_SIZE, mask=MASK):
    ciphertext = 0
    key = 0
    for element in public_key:
        r = random_integer(r_size)
        key += r
        ciphertext += (element * r)
    key &= mask    
    return ciphertext, key
    
def recover_key(ciphertext, private_key, s_shift=S_SHIFT, mask=MASK):
    inverse, q = private_key
    key = (((ciphertext * inverse) % q) >> s_shift) & mask
    return key
    
def test_encapsulate_key_recover_key():
    from unittesting import test_key_exchange
    test_key_exchange("uppers+qr", generate_keypair, encapsulate_key, recover_key, iterations=10000)
    
if __name__ == "__main__":
    test_encapsulate_key_recover_key()
    