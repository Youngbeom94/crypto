# as + e             
# s + aie          64 + 32 + 32      32 + 32 + 32 + 32         q = 128
#                  96 + 32 + 32      64 + 32 + 32 + 32         q = 160
#                 128 + 32 + 32      96 + 32 + 32 + 32         q = 192
#                 160 + 32 + 32     128 + 32 + 32 + 32         q = 224

#64    128        q = 128, s = 32 + 32 + 32, e = 32 + 32 + 32 + 32
#                                     q = 128, s = 64 + 32 + 32, e = 64 + 32 + 32 + 32
#                                                  128               160
#                    64    32  = 96   q = 160, 
#                    96    64  = 160  q = 192
#                    128   96  = 224  q

from crypto.utilities import random_integer, modular_inverse

SECURITY_LEVEL = 32
PADDING = 4

def generate_parameter_sizes(security_level=SECURITY_LEVEL, padding=PADDING):
    inverse_size = security_level    
    e_size = (security_level * 4) - padding
    s_shift = security_level * 8
    s_size = security_level * 5
    s_mask = ((2 ** (security_level * 8)) - 1)
    q_size = security_level * 7
    
    r_size = security_level
    return inverse_size, e_size, s_shift, s_size, s_mask, q_size

INVERSE_SIZE, E_SIZE, S_SHIFT, S_SIZE, S_MASK, Q_SIZE = generate_parameter_sizes(SECURITY_LEVEL, PADDING)
ENCRYPTION_PARAMETERS = (S_SIZE, S_SHIFT, E_SIZE)
DECRYPTION_PARAMETERS = (S_MASK, )

def generate_q(q_size=Q_SIZE):
    q_size *= 8 # to bits
    q_size += 1 # pad with 1 extra bit
    return (2 ** q_size) + 1 # + 1 required for correctness (so it's not a power of 2)       

Q = generate_q(Q_SIZE)

def generate_secret_key(inverse_size=INVERSE_SIZE, q=Q):
    shift = inverse_size * 8
    while True:
        decryption_key = random_integer(inverse_size) << shift
        try:
            encryption_key = modular_inverse(decryption_key, q)
        except ValueError:
            continue
        else:
            break
    return decryption_key, encryption_key
    
def encrypt(m, key, s_size=S_SIZE, s_shift=S_SHIFT, e_size=E_SIZE, q=Q):
    decryption_key, encryption_key = key
    s = (random_integer(s_size) << s_shift) | m
    e = random_integer(e_size)
    ciphertext = ((encryption_key * s) + e) % q
    return ciphertext
    
def decrypt(ciphertext, key, s_mask=S_MASK, q=Q):
    decryption_key, encryption_key = key
    return ((ciphertext * decryption_key) % q) & s_mask
    
def test_encrypt_decrypt():
    from unittesting import test_symmetric_encrypt_decrypt
    test_symmetric_encrypt_decrypt("secretkey", generate_secret_key, encrypt, decrypt, iterations=10000)
    
if __name__ == "__main__":
    test_encrypt_decrypt()
    
    
    