# (aa + bb)(c + (d/h))
# ach - bd
# d/h = x where log(x) = log(d) - log(h)
#       x = 32
#       d = 64

from hashlib import sha256, sha512
from crypto.utilities import random_integer, isqrt, bytes_to_integer

SECURITY_LEVEL = 8

def h(m, hash_algorithm=sha256):
    return bytes_to_integer(bytearray(hash_algorithm(m).digest()))
    
def is_square(n):
    return pow(isqrt(n), 2) == n
    
def generate_private_key(security_level=SECURITY_LEVEL):
    a = random_integer(security_level * 2)
    b = random_integer(security_level * 2)
    return a, b
    
def generate_public_key(private_key):
    a, b = private_key
    return pow(a, 2) + pow(b, 2)
    
def generate_keypair(security_level=SECURITY_LEVEL):
    private_key = generate_private_key(security_level)
    public_key = generate_public_key(private_key)
    return public_key, private_key
    
def sign(private_key, m, security_level=SECURITY_LEVEL):           
    a, b = private_key
    c = random_integer(security_level * 2)
    d = random_integer(security_level)
    hm = h(m)
    # (aa + bb) * (cc + dd) = (ac - bd)^2 + (ad + bc)^2
    # (aa + bb) * (cc + ddhh) = (ac - bdh)^2 + (adh + bc)^2
    # (aa + bb) * (cchh + ddhhhh) = (ach - bdhh)^2 + (adhh + bch)^2
    # (aa + bb) * h(cch + ddhhh) = (ach - bdhh)^2 + (adhh + bch)^2
    t = (pow(c, 2) * hm) + (pow(d * hm, 2) * hm)
    s = (a * c * hm) - (b * d * hm * hm)
    return t, s
    
def verify(public_key, signature, m):    
    t, s = signature        
    return is_square((t * public_key * h(m)) - pow(s, 2))
    
def test_sign_verify():
    public_key, private_key = generate_keypair()
    m = "Test message!"
    signature = sign(private_key, m)
    assert verify(public_key, signature, m) == True
    
    from math import log
    print("Private key size: {}".format(sum(log(item, 2) for item in private_key)))
    print("Public key size: {}".format(log(public_key, 2)))    
    print("Signature size: {}".format(sum(log(abs(item), 2) for item in signature)))
        
    m2 = "Forgery"
    forged_signature = (signature[0], (signature[1] / h(m)) * h(m2))
    print("Broken: {}".format(verify(public_key, forged_signature, m2)))
    
if __name__ == "__main__":
    test_sign_verify()
    
