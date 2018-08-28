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
    
def generate_challenge(parameters=PARAMETERS):
    return random_integer(parameters["r_size"])   
        
def prove(r, private_key, parameters=PARAMETERS):
    # (aa + bb) * (cc + dd) = (ac + bd)^2 + (ad - bc)^2
    #(aa + bb)r(cc + ddr) = (ac(sqrt(r)) - bdr)^2 + (adr + bc(sqrt(r)))^2    
    #(aa + bb)rr(cc + ddrr) = (acr - bdrr)^2 + (adrr + bcr)^2        
    a, b = private_key
    c = random_integer(parameters["c_size"])
    d = random_integer(parameters["d_size"])
        
    rr = r * r
    t = (c * c) + (d * d * rr)
    s = (a * d * rr) + (b * c * r)
    return t, s
    
def verify(proof, r, public_key):    
    t, s = proof        
    return is_square(abs((t * public_key * r * r) - pow(s, 2)))
    
def test_sign_verify():
    public_key, private_key = generate_keypair()
    challenge = generate_challenge()
    proof = prove(challenge, private_key)
    assert verify(proof, challenge, public_key) == True
    
    fake_r = generate_challenge() 
    fake_proof1 = ((proof[0] / challenge) * fake_r), ((proof[1] / challenge) * fake_r)
    fake_proof2 = ((proof[0] / challenge) * fake_r), ((proof[1] / challenge) * isqrt(fake_r))
    fake_proof3 = ((proof[0] / challenge) * isqrt(fake_r)), ((proof[1] / isqrt(challenge)) * fake_r)
    fake_proof4 = ((proof[0] / challenge) * isqrt(fake_r)), ((proof[1] / isqrt(challenge)) * isqrt(fake_r))
    fake_proof5 = ((proof[0] / isqrt(challenge)) * fake_r), ((proof[1] / challenge) * fake_r)
    fake_proof6 = ((proof[0] / isqrt(challenge)) * fake_r), ((proof[1] / challenge) * isqrt(fake_r))
    fake_proof7 = ((proof[0] / isqrt(challenge)) * isqrt(fake_r)), ((proof[1] / isqrt(challenge)) * fake_r)
    fake_proof8 = ((proof[0] / isqrt(challenge)) * isqrt(fake_r)), ((proof[1] / isqrt(challenge)) * isqrt(fake_r))
    
    for index, fake_proof in enumerate((fake_proof1, fake_proof2, fake_proof3, fake_proof4, 
                                        fake_proof5, fake_proof6, fake_proof7, fake_proof8)):
        if verify(fake_proof, fake_r, public_key):
            print("Broken by {}".format(index))
            raise SystemExit()        
    
    from math import log
    print("Private key size: {}".format(sum(log(item, 2) for item in private_key)))
    print("Public key size: {}".format(log(public_key, 2)))    
    print("Proof size: {}".format(sum(log(item, 2) for item in proof)))
    
if __name__ == "__main__":
    test_sign_verify()
    
