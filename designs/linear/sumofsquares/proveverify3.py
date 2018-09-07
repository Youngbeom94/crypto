from hashlib import sha256, sha512
from crypto.utilities import random_integer, isqrt, bytes_to_integer, is_prime

SECURITY_LEVEL = 32

def generate_parameters(security_level=SECURITY_LEVEL):
    parameters = {"ab_size" : (security_level * 2) + (security_level / 2),
                  "c_size" : security_level * 2, "d_size" : security_level,
                  "r_size" : security_level}
    return parameters

PARAMETERS = generate_parameters(SECURITY_LEVEL)
    
def is_square(n):
    return pow(isqrt(n), 2) == n
    
def generate_private_key(parameters=PARAMETERS):
    ab_size = parameters["ab_size"]
    a = random_integer(ab_size)
    while True:        
        b = random_integer(ab_size)
        if is_prime(pow(a, 2) + pow(b, 2)):
            break
    print("Generated a, b")
    c = random_integer(ab_size)
    while True:
        d = random_integer(ab_size)
        if is_prime(pow(c, 2) + pow(d, 2)):
            break    
    print("Generated c, d")
    x = (a * c) - (b * d)
    y = (a * d) + (b * c)
    
    assert (pow(x, 2) + pow(y, 2)) == (pow(a, 2) + pow(b, 2)) * (pow(c, 2) + pow(d, 2))
    return x, y
    
def generate_public_key(private_key):
    x, y = private_key
    return pow(x, 2) + pow(y, 2)
    
def generate_keypair(parameters=PARAMETERS):
    private_key = generate_private_key(parameters)
    public_key = generate_public_key(private_key)
    return public_key, private_key
    
def prove(private_key, parameters=PARAMETERS):       
    x, y = private_key
    pub_t, priv_t = generate_keypair(parameters)
    c, d = priv_t
    
    s = ((x * c) - (y * d), 
         (x * d) + (y * c))
    return pub_t, s
    
def verify(proof, public_key):    
    t, s = proof  
    s0, s1 = s
    return public_key * t == pow(s0, 2) + pow(s1, 2)
        
def test_prove_verify():
    public_key, private_key = generate_keypair()    
    proof = prove(private_key)
    assert verify(proof, public_key) == True   
    
    from math import log
    print("Private key size: {}".format(sum(log(abs(item), 2) for item in private_key)))
    print("Public key size: {}".format(log(public_key, 2)))    
    print("Proof size: {}".format(sum(log(item, 2) for item in proof)))
    
if __name__ == "__main__":
    test_prove_verify()
    
