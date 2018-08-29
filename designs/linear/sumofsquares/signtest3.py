from hashlib import sha256, sha512
from crypto.utilities import random_integer, isqrt, bytes_to_integer, is_prime

SECURITY_LEVEL = 32

def generate_parameters(security_level=SECURITY_LEVEL):
    parameters = {"ab_size" : (security_level * 2) + (security_level / 2),
                  "c_size" : security_level * 2, "d_size" : security_level,
                  "hash_algorithm" : sha256}
    return parameters

PARAMETERS = generate_parameters(SECURITY_LEVEL)
    
def h(m, parameters=PARAMETERS):
    hash_algorithm = parameters["hash_algorithm"]
    return bytes_to_integer(bytearray(hash_algorithm(m).digest()))
        
def is_square(n):
    return pow(isqrt(n), 2) == n
    
def generate_private_key(parameters=PARAMETERS):
    ab_size = parameters["ab_size"]
    while True:
        a = random_integer(ab_size)
        b = random_integer(ab_size)
        if not is_prime(pow(a, 2) + pow(b, 2)):
            break
    return a, b
    
def generate_public_key(private_key):
    a, b = private_key
    return pow(a, 2) + pow(b, 2)
    
def generate_keypair(parameters=PARAMETERS):
    private_key = generate_private_key(parameters)
    public_key = generate_public_key(private_key)
    return public_key, private_key
     
def sign(m, private_key, parameters=PARAMETERS):
    # (aa + bb) * (cc + dd) = (ac + bd)^2 + (ad - bc)^2    
    # (aa + bb)rr(cc + ddrr) = (acr - bdrr)^2 + (adrr + bcr)^2        
    a, b = private_key
    c = random_integer(parameters["c_size"])
    d = random_integer(parameters["d_size"])
    r = h(m)
    
    rr = r * r
    t = (c * c) + (d * d * rr)
    s = (a * d * rr) + (b * c * r)
    return t, s
    
def verify(proof, m, public_key):    
    t, s = proof   
    r = h(m)
    return is_square(abs((t * public_key * r * r) - pow(s, 2)))
    
def test_sign_verify():
    public_key, private_key = generate_keypair()
    message = "Sign here please"
    proof = sign(message, private_key)
    assert verify(proof, message, public_key) == True        
    
    broken = "Ella smash!"
    proof2 = proof[0], (proof[1] / h(message)) * h(broken)
    if verify(proof2, broken, public_key):
        print("Broken!")
        raise SystemExit()
        
    from crypto.designs.linear.homomorphic.latticebased.unittesting import test_sign_verify
    test_sign_verify("Quadratic sum signature test 3", generate_keypair, sign, verify, iterations=10000)
    
if __name__ == "__main__":
    test_sign_verify()
    