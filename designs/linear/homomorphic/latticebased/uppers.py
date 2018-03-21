#           224     32+32+96      160 + 96 = 256
#                                            224
from crypto.utilities import modular_inverse, random_integer

SECURITY_LEVEL = 32

def generate_parameter_sizes(security_level=SECURITY_LEVEL):
    from math import log
    inverse_size = security_level
    e_size = (security_level * 3) - 1
    s_size = (security_level * 5) - 1
    q_size = (security_level * 7) + 1
    
    r_size = security_level
    dimensions = q_size / r_size
    s_shift = (security_level * 6 * 8) + int(log(dimensions, 2))
    mask = (2 ** (security_level * 8)) - 1    
    return inverse_size, e_size, s_size, q_size, r_size, dimensions, s_shift, mask
    
INVERSE_SIZE, E_SIZE, S_SIZE, Q_SIZE, R_SIZE, DIMENSIONS, S_SHIFT, MASK = generate_parameter_sizes(SECURITY_LEVEL)

def find_q(q_size=Q_SIZE):
    from crypto.utilities import is_prime
    q = 2 ** (q_size * 8)
    offset = 1
    while not is_prime(q + offset):
        offset += 2
    return q, offset
    
#q, offset = find_q(Q_SIZE)    
#print q, offset
Q = (2 ** (Q_SIZE * 8)) + 787

def generate_private_key(inverse_size=INVERSE_SIZE, q=Q):
    inverse = random_integer(inverse_size)
    return inverse
    
def generate_public_key(private_key, e_size=E_SIZE, s_size=S_SIZE, dimensions=DIMENSIONS, q=Q, s_shift=S_SHIFT):
    a = modular_inverse(private_key, q)
    public_key = []
    payload_section = 1 << s_shift
    for element_number in range(dimensions):
        e = random_integer(e_size)
        s = random_integer(s_size)
        s |= payload_section
        element = ((a * s) + e) % q
        public_key.append(element)
    return public_key

def generate_keypair(inverse_size=INVERSE_SIZE, e_size=E_SIZE, s_size=S_SIZE, dimensions=DIMENSIONS, q=Q, s_shift=S_SHIFT):
    private_key = generate_private_key(inverse_size)
    public_key = generate_public_key(private_key, e_size, s_size, dimensions, q, s_shift)
    return public_key, private_key
    
def encapsulate_key(public_key, r_size=R_SIZE, q=Q, mask=MASK):
    ciphertext = 0
    key = 0
    for element in public_key:
        r = random_integer(r_size)
        key += r
        ciphertext += (element * r)
    key &= mask
    ciphertext %= q
    return ciphertext, key
    
def recover_key(ciphertext, private_key, s_shift=S_SHIFT, q=Q, mask=MASK):
    key = (((ciphertext * private_key) % q) >> s_shift) & mask
    return key
    
def test_encapsulate_key_recover_key():
    #pub, priv = generate_keypair()
    #s = random_integer(S_SIZE)
    #s |= 1 << S_SHIFT
    #e = random_integer(E_SIZE)
    #a = modular_inverse(priv, Q)
    #r = random_integer(R_SIZE)
    #print format(s, 'b')
    #raw_input()
    #rs = r * s
    #_r = (rs >> S_SHIFT) & MASK
    #print format(r, 'b')
    #print format(_r, 'b')
    #assert r == _r, (r, _r, len(format(r, 'b')), len(format(_r, 'b')))
    #c = (r * ((a * s) + e)) % Q
    #_r = (((c * priv) % Q) >> S_SHIFT) & MASK
    #assert (s * r) < Q
    #from math import log
    #aisize, esize, rsize = log(priv, 2), log(e, 2), log(r, 2)
    #assert s > (priv * e * r), (log(s, 2), aisize + esize + rsize)
    #print format(_r, 'b')
    #print format(r, 'b')
    #assert r == _r
    
    
    from unittesting import test_key_exchange
    test_key_exchange("uppers", generate_keypair, encapsulate_key, recover_key, iterations=10000)
    
if __name__ == "__main__":
    test_encapsulate_key_recover_key()
    