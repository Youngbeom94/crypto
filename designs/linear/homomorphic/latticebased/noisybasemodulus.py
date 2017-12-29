# xsa + x(se + wr)      32 32 160  32 32 32     32 32 32        q = 160 + 32 - 32 == 160
#                       64 64 64   64 64 32     64 32 32
from crypto.utilities import random_integer

SECURITY_LEVEL = 32
PADDING = 4

def generate_parameter_sizes(security_level=SECURITY_LEVEL, padding=PADDING):
    a_size = q_size = security_level * 5
    #a_size -= (security_level * 2)
    
    s_size = r_size = security_level
    e_size = s_size * 2 #q_size - (s_size * 2)
    #s_size *= 2

    secret_shift = (q_size * 8) - (security_level * 8) + (padding * 8)
    return a_size, q_size, s_size, e_size, r_size, secret_shift
    
A_SIZE, Q_SIZE, S_SIZE, E_SIZE, R_SIZE, SECRET_SHIFT = generate_parameter_sizes(SECURITY_LEVEL)
A = random_integer(A_SIZE)
Q = random_integer(Q_SIZE)
while A >= Q:
    A = random_integer(A_SIZE)
    Q = random_integer(Q_SIZE)
    
def generate_private_key(s_size=S_SIZE):
    return random_integer(s_size)
    
def generate_public_key(private_key, a=A, q=Q, e_size=E_SIZE, r_size=R_SIZE):
    e = random_integer(e_size)
    r = random_integer(r_size)
    s = private_key
    return (s * (a + e)) % (q + r)
    
def generate_keypair(s_size=S_SIZE, a=A, q=Q, e_size=E_SIZE, r_size=R_SIZE):
    private_key = generate_private_key(s_size)
    public_key = generate_public_key(private_key, a, q, e_size, r_size)
    return public_key, private_key
    
def key_agreement(public_key2, private_key1, q=Q, shift=SECRET_SHIFT):
    return ((public_key2 * private_key1) % q) >> shift
    
def unit_test():
    from unittesting import test_key_agreement
    test_key_agreement("noisybase+modulus", generate_keypair, key_agreement, iterations=10000)
    
if __name__ == "__main__":
    unit_test()
    