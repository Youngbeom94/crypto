from math import log, ceil
from operator import mul as multiply

from crypto.utilities import random_integer, modular_inverse, gcd

SECURITY_LEVEL = 32

def generate_parameters(security_level=SECURITY_LEVEL):
    parameters = dict()
    parameters["inverse_size"] = inverse_size = security_level    
    parameters["x_size"] = x_size = security_level 
    
    parameters["q_size"] = q_size = (((inverse_size * 2) + x_size + 1) * 8)
        
    parameters["dimensions"] = dimensions = q_size / security_level
    parameters["r_size"] = security_level
    parameters["inverse_shift"] = (x_size * 8) + int(ceil(log(dimensions, 2))) # second term adds headroom for additions
    parameters["lsb_mask"] = (2 ** (x_size * 8)) - 1
    parameters["lsb_modulus"] = 2 ** (x_size * 8)
    return parameters
    
PARAMETERS = generate_parameters(SECURITY_LEVEL)
    
def find_q(parameters=PARAMETERS):
    from crypto.utilities import is_prime
    q_size = parameters["q_size"]
    offset = 1
    q_base = (2 ** q_size)
    while not is_prime(q_base + offset):
        offset += 2
    return q_base, offset
    
#Q_BASE, OFFSET = find_q(PARAMETERS)    
#print OFFSET
Q = (2 ** PARAMETERS["q_size"]) + 247

def generate_secret_key(parameters=PARAMETERS, q=Q):            
    short_inverses = [(random_integer(parameters["inverse_size"]) << parameters["inverse_shift"]) + 1 for count in range(4)]
    decryption_scalar = reduce(multiply, short_inverses) % q  # a * b * c * d mod q
    
    a, b, c, d = [modular_inverse(element, q) for element in short_inverses]                             
    encryption_vector = ((b * c * d) % q,
                         (c * d * a) % q,
                         (d * a * b) % q,
                         (a * b * c) % q)  
    return encryption_vector, decryption_scalar
        
def secret_split(m, size, count, modulus):    
    splits = [random_integer(size) for counter in range(count - 1)]
    splits.append((m - sum(splits)) % modulus)    
    return splits
     
def dot_product(e, m):
    return sum((e[i] * m[i] for i in range(len(e))))
        
def encrypt(m, key, parameters=PARAMETERS, q=Q):    
    message_vector = secret_split(m, parameters["x_size"], 4, parameters["lsb_modulus"])       
    encryption_vector = key[0]    
    ciphertext = dot_product(encryption_vector, message_vector) % q    
    return ciphertext
    
def decrypt(ciphertext, key, parameters=PARAMETERS, q=Q):    
    decryption_scalar = key[1]
    return ((ciphertext * decryption_scalar) % q) & parameters["lsb_mask"]
    
def test_encrypt_decrypt():
    key = generate_secret_key()
    m0 = 0
    m1 = 1
    mr = random_integer(SECURITY_LEVEL)
    
    c0 = encrypt(m0, key)
    c1 = encrypt(m1, key)
    cr = encrypt(mr, key)
    
    p0 = decrypt(c0, key)
    p1 = decrypt(c1, key)
    pr = decrypt(cr, key)
    
    assert (m0 == p0), (m0, p0)
    assert (m1 == p1), (m1, p1)
    assert (mr == pr), (mr, pr)
    
    from unittesting import test_symmetric_encrypt_decrypt
    test_symmetric_encrypt_decrypt("axby2", generate_secret_key, encrypt, decrypt, iterations=10000)
    
if __name__ == "__main__":
    test_encrypt_decrypt()
    