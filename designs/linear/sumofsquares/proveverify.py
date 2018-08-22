from crypto.utilities import random_integer, isqrt

SECURITY_LEVEL = 32

def is_square(n):
    return pow(isqrt(n), 2) == n
    
def generate_private_key(security_level=SECURITY_LEVEL):
    a = random_integer(security_level)
    b = random_integer(security_level)
    return a, b
    
def generate_public_key(private_key):
    a, b = private_key
    return pow(a, 2) + pow(b, 2)
    
def generate_keypair(security_level=SECURITY_LEVEL):
    private_key = generate_private_key(security_level)
    public_key = generate_public_key(private_key)
    return public_key, private_key
    
def prove(private_key, security_level=SECURITY_LEVEL):
    # (aa + bb)(cc + dd) = (ac - bd)^2 + (ad + bc)^2
    a, b = private_key
    c = random_integer(security_level)
    d = random_integer(security_level)
    
    t = pow(c, 2) + pow(d, 2)
    ac = a * c
    bd = b * d
    s = max(ac, bd) - min(ac, bd)    
    return t, s
    
def verify(public_key, proof):
    t, s = proof
    s2 = pow(s, 2)
    return is_square((t * public_key) - s2)
    
def test_prove_verify():
    public_key, private_key = generate_keypair()
    proof = prove(private_key)
    assert verify(public_key, proof) == True
    
    from math import log
    print("Private key size: {}".format(sum(log(item, 2) for item in private_key)))
    print("Public key size: {}".format(log(public_key, 2)))    
    print("Proof size: {}".format(sum(log(item, 2) for item in proof)))
        
if __name__ == "__main__":
    test_prove_verify()
    