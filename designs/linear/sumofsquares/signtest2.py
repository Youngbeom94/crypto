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
    # (aa + bb) * (cc + ddhh) = (ac + bdh)^2 + (adh - bc)^2
    # (aa + bb) * (cchh + ddhhhh) = (ach + bdhh)^2 - (adhh + bch)^2
    # (aa + bb) * h(cch + ddhhh) = (ach + bdhh)^2 - (adhh + bch)^2          
    a, b = private_key
    c = random_integer(parameters["c_size"])
    d = random_integer(parameters["d_size"])
    hm = h(m)
    
    ch = c * hm
    dhh = d * hm * hm
    t = (c * ch) + (d * dhh * hm)                 # h(cc + ddhh) / h = cc + ddhh = x + yz
    s = (a * ch) + (b * dhh)                      # h(ac + bdh)  / h = ac + bdh 
    return t, s
    
def verify(signature, m, public_key):    
    t, s = signature        
    return is_square(abs((t * public_key * h(m)) - pow(s, 2)))
    
def test_sign_verify():
    public_key, private_key = generate_keypair()
    m = "Test message!"
    signature = sign(m, private_key)
    assert verify(signature, m, public_key) == True
    
    m2 = "Forgery"
    forged_signature = (signature[0], (signature[1] / h(m)) * h(m2))
    if verify(forged_signature, m2, public_key):
        print("Broken!")
    from crypto.designs.linear.homomorphic.latticebased.unittesting import test_sign_verify
    test_sign_verify("Quadratic sum signature test 2", generate_keypair, sign, verify, iterations=10000)
    
if __name__ == "__main__":
    test_sign_verify()
    
