# g^s * h^r
from crypto.utilities import random_integer, modular_inverse, big_prime

SECURITY_LEVEL = 32

def generate_parameters(security_level=SECURITY_LEVEL):
    k_size = security_level       
    r_size = s_size = security_level
    p_size = security_level
    generator = 3
    share_size = security_level
    parameters = {"k_size" : k_size, "r_size" : r_size, "s_size" : s_size,                  
                  "p_size" : p_size, "generator" : generator, "share_size" : share_size}
    return parameters
    
def find_p(parameters):
    from crypto.utilities import is_prime
    p_size = parameters["p_size"]
    p = 2 ** ((p_size * 8) + 1)    
    offset = 1
    while not is_prime(p + offset):
        offset += 2
    return p, offset
    
PARAMETERS = generate_parameters(SECURITY_LEVEL)      
#P_BASE, OFFSET = find_p(PARAMETERS)
#print OFFSET
#P = P_BASE + OFFSET    
#P = (2 ** ((PARAMETERS["p_size"] * 8) + 1)) + 155
P = (2 ** 256) + 230191
PARAMETERS["p"] = P

def secret_split(m, security_level, shares, modulus):
    shares = [random_integer(security_level) for count in range(shares - 1)]
    shares_product = reduce(lambda x, y: (x * y) % modulus, shares)
    remaining_share = (modular_inverse(shares_product, modulus) * m) % modulus
    shares.append(remaining_share)
    return shares
    
def generate_key(parameters=PARAMETERS):
    k_size = parameters["k_size"]
    p = parameters['p']
    while True:
        k1 = random_integer(k_size)
        k2 = random_integer(k_size)
        try:
            k1i = modular_inverse(k1, p - 1)
            k2i = modular_inverse(k2, p - 1)
        except ValueError:
            continue
        else:
            break
    return (k1, k2)
    
def private_key_encrypt(m, key, parameters=PARAMETERS):
    p = parameters['p']
    x, y = secret_split(m, parameters["share_size"], 2, p)
    k1, k2 = [modular_inverse(k, p - 1) for k in key]
    return pow(x, k1, p), pow(y, k2, p)
    
def private_key_decrypt(ciphertext, key, parameters=PARAMETERS):    
    p = parameters['p']
    c1, c2 = ciphertext
    k1i, k2i = key 
    return (pow(c1, k1i, p) * pow(c2, k2i, p)) % p
    
def multiply(c1, c2, p=P):
    return [(c1[index] * c2[index]) % p for index in range(len(c1))]
    
def scalar_exponentiation(ciphertext, exponent, p=P):
    return [pow(element, exponent, p) for element in ciphertext]
    
def generate_private_key(parameters=PARAMETERS):
    return generate_key(parameters)
    
def generate_public_key(private_key, parameters=PARAMETERS):
    public_key = [private_key_encrypt(parameters["generator"], private_key, parameters),
                  private_key_encrypt(1, private_key, parameters)]    
    return public_key
    
def generate_keypair(parameters=PARAMETERS):    
    private_key = generate_private_key(parameters)
    public_key = generate_public_key(private_key, parameters)
    return public_key, private_key
    
def encapsulate_key(public_key, parameters=PARAMETERS):        
    p = parameters["p"]
    s = random_integer(parameters["s_size"])
    r = random_integer(parameters["r_size"])
    shared_secret = pow(parameters["generator"], s, p)
    encrypted_secret = scalar_exponentiation(public_key[0], s, p)
    randomizer = scalar_exponentiation(public_key[1], r, p)
    ciphertext = multiply(encrypted_secret, randomizer, p)
    return ciphertext, shared_secret
    
def recover_key(ciphertext, private_key, parameters=PARAMETERS):
    return private_key_decrypt(ciphertext, private_key, parameters)    

def encrypt_public_key(public_key, parameters=PARAMETERS):
    p = parameters["p"]
    r = random_integer(parameters["r_size"])
    randomized_1 = scalar_exponentiation(public_key[1], r, p)
    randomized_g = multiply(public_key[0], randomized_1, p)
    return (randomized_g, randomized_1)
    
def test_encapsulate_key():
    from crypto.designs.linear.homomorphic.latticebased.unittesting import test_key_exchange
    test_key_exchange("double DH", generate_keypair, encapsulate_key, recover_key, iterations=10000)       

    print("Beginning encrypted public key unit test...")
    public_key, private_key = generate_keypair()
    for iteration in range(100):
        pubic_key2 = encrypt_public_key(public_key)
        ciphertext, secret = encapsulate_key(pubic_key2)
        _secret = recover_key(ciphertext, private_key)
        assert secret == _secret
    print("...done")    
    
if __name__ == "__main__":
    test_encapsulate_key()
    