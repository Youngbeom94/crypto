import hashlib

from crypto.utilities import big_prime, bytes_to_integer
from breaktest import sq2 as find_squares

SECURITY_LEVEL = 4

def generate_parameters(security_level=SECURITY_LEVEL):
    parameters = {"ab_size" : (security_level * 2) + (security_level / 2),
                  "c_size" : security_level * 2, "d_size" : security_level,
                  "r_size" : security_level, "hash_algorithm" : "sha256",
                  "hash_size" : 32}
    return parameters

PARAMETERS = generate_parameters(SECURITY_LEVEL)

def h(m, parameters=PARAMETERS):
    hash_function = getattr(hashlib, parameters["hash_algorithm"])
    return bytes_to_integer(bytearray(hash_function(m).digest()))
        
def generate_private_key(parameters=PARAMETERS):
    ab_size = parameters["ab_size"]    
    while True:
        p = big_prime(ab_size)
        if p % 4 == 1:            
            a, b = find_squares(p)            
            break    
    while True:
        q = big_prime(ab_size)
        if q % 4 == 1:            
            c, d = find_squares(q)            
            break    
    n = p * q
    x = (a * c) - (b * d)
    y = (a * d) + (b * c)
    assert pow(x, 2) + pow(y, 2) == n
    return x, y
    
def generate_public_key(private_key):
    x, y = private_key
    return pow(x, 2) + pow(y, 2)
    
def generate_keypair(parameters=PARAMETERS):
    private_key = generate_private_key(parameters)
    public_key = generate_public_key(private_key)
    return public_key, private_key
    
def sign(m, private_key, parameters=PARAMETERS):       
    x, y = private_key    
    hm = h(m)
    hash_size = parameters["hash_size"]
    keypairs = [generate_keypair(parameters) for count in range(hash_size)]
    commitment = [keypair[0] for keypair in keypairs]
    proof = []
    for bit in range(hash_size):
        if hm & (1 << bit) == 1:            
            proof.append(keypairs[bit][1])
        else:
            c, d = keypairs[bit][1]
            s = ((x * c) - (y * d),
                 (x * d) + (y * c))
            proof.append(s)
    return commitment, proof
    
def verify(signature, m, public_key, parameters=PARAMETERS):    
    commitment, proof = signature
    hm = h(m)
    for bit in range(parameters["hash_size"]):
        c2plusd2 = commitment[bit]
        if hm & (1 << bit) == 1:            
            c, d = proof[bit]
            if pow(c, 2) + pow(d, 2) != c2plusd2:
                return False
        else:
            xc_yd, xd_yc = proof[bit]
            if public_key * c2plusd2 != pow(xc_yd, 2) + pow(xd_yc, 2):
                return False
    return True      
        
def test_prove_verify():    
    from crypto.designs.linear.homomorphic.latticebased.unittesting import test_sign_verify
    test_sign_verify("Quadratic sum signature test 4", generate_keypair, sign, verify, iterations=100)
    
if __name__ == "__main__":
    test_prove_verify()
    
