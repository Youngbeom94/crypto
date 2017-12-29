# short inverse signature
# m == as + e
# signature = s # recover via ai(as + e) = s + ai(e); % ai = s
# verifier = msb(a * s) == msb(m)
from math import log
from crypto.utilities import random_integer, modular_inverse

SECURITY_LEVEL = 32
PADDING = 0

def generate_parameter_sizes(security_level=SECURITY_LEVEL, padding=PADDING):
    ai_size = security_level # will ultimately be security_level * 2 after power of two is shifted in later
    k_size = security_level
    
    s_size = security_level
    e_size = security_level * 2
    
    q_size = (ai_size * 2) + e_size
    shift = security_level * 8 * 4
    msb = (((2 ** (q_size * 8)) - 1) >> shift) << shift
    return ai_size, k_size, s_size, q_size, msb, shift
    
INVERSE_SIZE, K_SIZE, S_SIZE, Q_SIZE, MSB, SIG_SHIFT = generate_parameter_sizes(SECURITY_LEVEL, PADDING)    

def generate_q(q_size=Q_SIZE):
    q_size_in_bits = q_size * 8    
    q = random_integer(q_size)
    while log(q, 2) < q_size_in_bits - 1:
        q = random_integer(q_size)
    return q

Q = generate_q(Q_SIZE)
    
def generate_private_key(inverse_size=INVERSE_SIZE, k_size=K_SIZE, q=Q):
    shift = inverse_size * 8
    while True:
        ai = random_integer(inverse_size) << shift
        q_k = q + random_integer(k_size)
        try:
            modular_inverse(ai, q_k)
        except ValueError:
            continue
        else:
            break
    return ai, q_k
    
def generate_public_key(private_key):
    ai, q_k = private_key
    a = modular_inverse(ai, q_k)
    return a
    
def generate_keypair(inverse_size=INVERSE_SIZE, k_size=K_SIZE, q=Q):
    private_key = generate_private_key(inverse_size, k_size, q)
    public_key = generate_public_key(private_key)
    return public_key, private_key
    
def sign(message, private_key):    
    if message < 2 ** 128:
        raise ValueError("Message too small")
    ai, q_k = private_key
    signature = ((ai * message) % q_k) % ai    
    return signature
    
def verify(signature, message, public_key, q=Q, msb=MSB):    
    verifier = ((public_key * signature) % q) & msb
    if verifier == msb & message:
        return True
    else:
        return False
        
def unit_test():
    from crypto.designs.linear.homomorphic.latticebased.unittesting import test_sign_verify
    test_sign_verify("short_inverse_signature", generate_keypair, sign, verify, iterations=10000, message_size=Q_SIZE)
    
if __name__ == "__main__":
    unit_test()
    