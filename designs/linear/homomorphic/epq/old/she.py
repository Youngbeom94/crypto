""" epq_she - Somewhat Homomorphic Encryption (symmetric encryption)
Effectively equivalent to the algoritm presented in Fully Homomorphic Encryption Over The Integers, except performed over finite fields instead.
(Uses short inverse only, Does not use noisy modulus or trapdoor.py)
Can be used to instantiate a public key scheme.

public parameters:
    P = big_prime(prime_size)
    
key generation:
    a_i = random_integer(short_inverse_size)
    a = modular_inverse(a_i, P)
    secret_key = (a_i, a)

encryption:
    s = random_integer(security_level) || bit
    e = random_integer(security_level)
    ciphertext = as + e mod P

decryption:
    bit = ai * ciphertext mod P mod ai mod 2    
    
homomorphic properties:
    c1 + c2 == bit1 XOR bit2
    c1 * c2 == bit1 AND bit2"""    
from utilities import big_prime, modular_inverse, random_integer

P = 15624554725589300108028359420813649421358687587335913932516791047818722590040554599807493933062956667312163710471909420935282181282705895744425684147635747355088535662464428923668351746572873233876824347271520785884923390213864707521193624103726993925639378366518319658181903836973013201204557500590779473711073416857030483827553309270379961411727642118205474395101535197662351883169453

def generate_secret_key(inverse_size=64, p=P):
    """ usage: generate_secret_key(inverse_size=64, p=P) => a, ai
    
        Returns 2 integers. 
        The size of the inverse places a limit on how many cipher multiplications may be performed. """
    ai = random_integer(inverse_size)
    return modular_inverse(ai, p), ai
    
def encrypt(bit, key, s_size=31, e_size=16, p=P):
    """ usage: encrypt(bit, key, 
                       s_size=31, e_size=16, p=P) => ciphertext
                       
        Returns a ciphertext integer. """
    a, ai = key    
    s = (random_integer(s_size) >> 1) << 1    
    e = random_integer(e_size)
    return ((a * (s + bit)) + e) % p
    
def decrypt(ciphertext, key, p=P, depth=1):
    """ usage: decrypt(ciphertext, key,
                       p=P, depth=1): => plaintext
                       
        Returns a plaintext bit.
        The depth argument must be set to the number of ciphertext multiplications performed, starting at 1
            - a fresh ciphertext that has not been multiplied has depth 1
            - a ciphertext that is the product of 2 ciphertext has depth 2
            - etc
            - key size must also facilitate the desired depth"""
    a, ai = key
    return (((ciphertext * pow(ai, depth, p)) % p) % ai) & 1
        
def test_encrypt_decrypt():
    key = generate_secret_key()
    iterations = 10000
    for count in range(iterations):
        bit = random_integer(1) & 1
        ciphertext = encrypt(bit, key)
        _bit = decrypt(ciphertext, key)
        if bit != _bit:
            raise Warning("cipher.py unit test failed.")
    
    for count in range(iterations):
        for bit1 in range(2):
            for bit2 in range(2):
                assert bit1 in (0, 1)
                assert bit2 in (0, 1)
                ciphertext1 = encrypt(bit1, key)
                ciphertext2 = encrypt(bit2, key)
                ciphertext3 = ciphertext1 + ciphertext2
                ciphertext4 = ciphertext1 * ciphertext2
                plaintext3 = decrypt(ciphertext3, key)
                plaintext4 = decrypt(ciphertext4, key, depth=2)
                assert plaintext3 == (bit1 ^ bit2)
                assert plaintext4 == (bit1 & bit2), (bit1, bit2)
    print("cipher.py unit test passed")        
            
if __name__ == "__main__":
    test_encrypt_decrypt()
    