from hashlib import sha256, sha512
from crypto.utilities import big_prime
from breaktest import sq2 as find_squares

SECURITY_LEVEL = 32

def generate_parameters(security_level=SECURITY_LEVEL):
    parameters = {"ab_size" : (security_level * 2) + (security_level / 2),
                  "c_size" : security_level * 2, "d_size" : security_level,
                  "r_size" : security_level}
    return parameters

PARAMETERS = generate_parameters(SECURITY_LEVEL)
    
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
    proof_size = 0
    for item in proof:
        try:
            for _item in item:
                proof_size += log(_item, 2)
        except TypeError:
            proof_size += log(item, 2)
    print("Proof size: {}".format(proof_size))
    
if __name__ == "__main__":
    test_prove_verify()
    
