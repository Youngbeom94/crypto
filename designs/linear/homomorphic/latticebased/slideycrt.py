from crypto.utilities import modular_inverse, random_integer, big_prime

SECURITY_LEVEL = 32
PADDING = 4

def product(factors, _multiply=lambda x, y: x * y):
    return reduce(_multiply, factors)
    
def chinese_remainder(n, a):
    sum = 0
    prod = product(n)
 
    for n_i, a_i in zip(n, a):
        p = prod / n_i
        sum += a_i * modular_inverse(p, n_i) * p
    return sum % prod
    
def generate_parameter_sizes(security_level=SECURITY_LEVEL, padding=PADDING):
    q_size = security_level * 20
        
    inverse_size = security_level 
    shift = security_level * 8
    r_size = security_level * 15
    a_shift = security_level * 14 * 8
    
    s_size = security_level * 3
    e_shift = ((security_level * 18) * 8) - (padding * 8)
    
    mask = (2 ** (security_level * 8)) - 1
    return q_size, inverse_size, shift, r_size, a_shift, s_size, e_shift, mask
    
Q_SIZE, INVERSE_SIZE, SHIFT, R_SIZE, A_SHIFT, S_SIZE, E_SHIFT, MASK = generate_parameter_sizes(SECURITY_LEVEL, PADDING)
PRIME_SIZE = 8
PRIME_COUNT = Q_SIZE / PRIME_SIZE
Q_ps = [big_prime(PRIME_SIZE) for count in range(PRIME_COUNT + PADDING)]
Q = product(Q_ps)

def generate_private_key(inverse_size=INVERSE_SIZE, r_size=R_SIZE, q=Q, shift=SHIFT):
    while True:
        inverse = random_integer(inverse_size) << shift
        r = random_integer(r_size)
        try:
            modular_inverse(inverse, q + r)
        except ValueError:
            continue
        else:
            break        
    return inverse, r
    
def generate_public_key(private_key, q=Q, a_shift=A_SHIFT):
    ai, r = private_key    
    a = modular_inverse(ai, q + r)
    return (a >> a_shift) << a_shift
    
def generate_keypair(inverse_size=INVERSE_SIZE, r_size=R_SIZE, q=Q, shift=SHIFT):
    private_key = generate_private_key(inverse_size, r_size, q, shift)
    public_key = generate_public_key(private_key, q)
    return public_key, private_key
    
def encapsulate_key(public_key, s_size=S_SIZE, e_shift=E_SHIFT, q_ps=Q_ps, mask=MASK, a_shift=A_SHIFT):       
    a = public_key
    s = random_integer(s_size)            
    ciphertext = chinese_remainder(q_ps, ((a * s) for count in xrange(len(q_ps))))
    #_ciphertext = (a * s) % Q
    #assert ciphertext == _ciphertext
    secret = s & mask            
    return ciphertext >> e_shift, secret
    
def recover_key(ciphertext, private_key, q=Q, e_shift=E_SHIFT, mask=MASK):
    ai, r = private_key
    return (((ciphertext << e_shift) * ai) % (q + r)) & mask
   
def unit_test():
    from unittesting import test_key_exchange
    test_key_exchange("slideyCRT", generate_keypair, encapsulate_key, recover_key, iterations=10000, key_size=SECURITY_LEVEL)
    
if __name__ == "__main__":
    unit_test()
    