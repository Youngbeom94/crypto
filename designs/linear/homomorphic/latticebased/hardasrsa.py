#     es + r mod n + k
#     s + dr mod n + k
#     
#                             k = n / 2
#                             d + k + s = n
#                             32  48 + s = 96
#                             s = 16
#     
#                             24 + 48 + s = 96
#                             72 + s = 96
#                             s = 24

# n = p * q
# totient(n) = (p - 1) * (q - 1) = n - p - q + 1 = n - k
# given e, n, recovering d implies ability to factor n
#    recovering private key from this design implies ability to factor RSA moduli
#   - but public key operation is not guaranteed to be hard to invert

from crypto.utilities import random_integer, modular_inverse, is_prime

SECURITY_LEVEL = 24

def generate_parameters(security_level=SECURITY_LEVEL):
    parameters = {"d_size" : security_level, "k_size" : security_level * 2,
                  "s_size" : security_level, "n_size" : security_level * 4,
                  "r_shift" : (security_level * 3)}
    return parameters
    
PARAMETERS = generate_parameters(SECURITY_LEVEL)

def generate_n(n_size):    
    # ensures N is exactly the size it is supposed to be
    factor_size = n_size / 2
    most_significant_bit = 1 << (factor_size * 8) 
    while True:
        p = random_integer(factor_size) | most_significant_bit
        if is_prime(p):
            break
    while True:
        q = random_integer(factor_size) | most_significant_bit
        if is_prime(q):
            break    
    n = p * q
    return n
    
PARAMETERS['N'] = generate_n(PARAMETERS["n_size"])
    
def generate_private_key(parameters=PARAMETERS):        
    k = random_integer(parameters["k_size"])
    n = parameters['N']
    n_k = n + k
    while True:        
        d = random_integer(parameters["d_size"]) | (1 << (parameters["d_size"] * 8)) # high bit is set to ensure d > s
        try:
            e = modular_inverse(d, n_k)
        except ValueError:
            continue
        else:
            break
    return d, n_k
    
def generate_public_key(private_key):    
    d, n_k = private_key
    e = modular_inverse(d, n_k)
    return e
    
def generate_keypair(parameters=PARAMETERS):
    private_key = generate_private_key(parameters)
    public_key = generate_public_key(private_key)
    return public_key, private_key
    
def encapsulate_key(public_key, parameters=PARAMETERS):
    s = random_integer(parameters["s_size"]) >> 1 # ensures d > s
    c = ((public_key * s) % parameters['N']) >> parameters["r_shift"]
    return c, s
    
def recover_key(c, private_key, parameters=PARAMETERS):
    d, n_k = private_key
    c <<= parameters["r_shift"]
    return ((d * c) % n_k) % d
    
def test_encapsulate_key_recover_key():
    from unittesting import test_key_exchange
    test_key_exchange("hard_as_RSA", generate_keypair, encapsulate_key, recover_key, iterations=10000, key_size=SECURITY_LEVEL)
    
if __name__ == "__main__":
    test_encapsulate_key_recover_key()
    