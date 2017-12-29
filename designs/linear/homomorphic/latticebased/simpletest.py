from crypto.utilities import random_integer

SECURITY_LEVEL = 1
A = random_integer(3 * SECURITY_LEVEL)
Q = random_integer(3 * SECURITY_LEVEL)
if Q > A:
    A, Q = Q, A
E_SHIFT = 4#SECURITY_LEVEL * 8
S_SHIFT = (3 * SECURITY_LEVEL * 8) - 4#(SECURITY_LEVEL * 8)

def generate_private_key(size=SECURITY_LEVEL):
    private_key = random_integer(size)
    while not private_key:
        private_key = random_integer(size)
    return private_key
    
def generate_public_key(private_key, a=A, q=Q, e_shift=E_SHIFT):       
    public_key = ((a * private_key) % q) >> e_shift # compressed
    if public_key == 0:
        raise ValueError("Bad parameter/private key combination (public_key == 0)")
    return public_key
    
def generate_keypair(size=SECURITY_LEVEL, a=A, q=Q, e_shift=E_SHIFT):
    private_key = generate_private_key(size)
    public_key = generate_public_key(private_key, a, q, e_shift)
    return public_key, private_key
    
def key_agreement(public_key2, private_key1, q=Q, e_shift=E_SHIFT, s_shift=S_SHIFT):
    if public_key2 == 1:
        raise ValueError("Insecure public key value: 1")
    public_key2 = public_key2 << e_shift # uncompressed
    shared_secret = ((public_key2 * private_key1) % q) >> s_shift
    #if shared_secret == 0:
    #    raise ValueError("Shared secret is 0")
    return shared_secret
    
def unit_test():        
    for count in range(10000):
        try:
            public1, private1 = generate_keypair()
            public2, private2 = generate_keypair()
        except ValueError:
            continue
        share1 = key_agreement(public2, private1)
        share2 = key_agreement(public1, private2)
        assert share1 == share2, (count, share1, share2, public1, private1, public2, private2)
        
        #test_break = (((public1 << E_SHIFT) * (public2 << E_SHIFT) * ai) % Q) >> S_SHIFT
        #assert test_break != share1
    print("Simple key exchange unit test complete")
    
if __name__ == "__main__":
    unit_test()
    