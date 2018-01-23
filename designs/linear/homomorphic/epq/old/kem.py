""" epq_kem - key encapsulation mechanism """
from crypto.utilities import random_integer
import trapdoor

__all__ = ["generate_parameter_sizes", "generate_keypair", "encapsulate_key", "recover_key"]

generate_parameter_sizes = trapdoor.generate_parameter_sizes
generate_keypair = trapdoor.generate_keypair

def encapsulate_key(public_key, s_size=trapdoor.S_SIZE, e_shift=trapdoor.E_SHIFT, q=trapdoor.Q, mask=trapdoor.MASK):
    s = random_integer(s_size)
    ciphertext = trapdoor.public_key_operation(public_key, s, e_shift, q, mask)
    secret = s & mask
    return ciphertext, secret
    
def recover_key(ciphertext, private_key, q=trapdoor.Q, e_shift=trapdoor.E_SHIFT, mask=trapdoor.MASK):
    secret = trapdoor.private_key_operation(ciphertext, private_key, q, e_shift, mask)
    return secret
    
def unit_test():
    from unittesting import test_key_exchange
    test_key_exchange("epq_kem(slidey2)", generate_keypair, encapsulate_key, recover_key, iterations=10000, key_size=trapdoor.SECURITY_LEVEL)
    
if __name__ == "__main__":
    unit_test()
    
