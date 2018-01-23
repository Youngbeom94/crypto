""" epq_pke - public key encryption """
from crypto.utilities import random_integer
import trapdoor

generate_keypair = trapdoor.generate_keypair
M_SIZE = trapdoor.SECURITY_LEVEL
ARMOR_SIZE = trapdoor.S_SIZE - M_SIZE

def encrypt(m, public_key, armor_size=ARMOR_SIZE, e_shift=trapdoor.E_SHIFT, q=trapdoor.Q, mask=trapdoor.MASK):
    s = random_integer(trapdoor.S_SIZE)
    shift = trapdoor.SECURITY_LEVEL * 8
    s >>= shift
    s <<= shift
    padded_m = m | s
    ciphertext = trapdoor.public_key_operation(public_key, padded_m, e_shift, q, mask)        
    return ciphertext
    
def decrypt(ciphertext, private_key, q=trapdoor.Q, e_shift=trapdoor.E_SHIFT, mask=trapdoor.MASK):
    m = trapdoor.private_key_operation(ciphertext, private_key, q, e_shift, mask)    
    return m
    
def unit_test():
    from unittesting import test_asymmetric_encrypt_decrypt
    test_asymmetric_encrypt_decrypt("epq_pke(slidey2)", generate_keypair, encrypt, decrypt, iterations=10000, plaintext_size=M_SIZE)
    
if __name__ == "__main__":
    unit_test()
    
