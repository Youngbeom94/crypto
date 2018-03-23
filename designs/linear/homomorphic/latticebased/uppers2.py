from crypto.utilities import modular_inverse, random_integer, gcd

SECURITY_LEVEL = 32

def generate_parameter_sizes(security_level=SECURITY_LEVEL):
    from math import log
    parameters = dict()
    parameters["inverse_size"] = security_level
    parameters["e_shift"] = ((security_level * 4) - 2) * 8
    parameters["s_size"] = (security_level * 5) - 1
    parameters["q_size"] = q_size = (security_level * 7) + 4    
    
    parameters["r_size"] = r_size = security_level
    parameters["dimensions"] = dimensions =  q_size / r_size
    parameters["s_shift"] = (security_level * 6 * 8) + int(log(dimensions, 2))
    parameters["mask"] = (2 ** (security_level * 8)) - 1    
    parameters["r_modulus"] = 2 ** (security_level * 8)
    return parameters
    
PARAMETERS = generate_parameter_sizes(SECURITY_LEVEL)

def generate_private_key(parameters=PARAMETERS):
    inverse_size = parameters["inverse_size"]
    q_size = parameters["q_size"]    
    while True:
        inverse = random_integer(inverse_size)
        q = random_integer(q_size)    
        try:
            modular_inverse(inverse, q)
        except ValueError:
            continue
        else:
            if gcd(inverse, q) == 1:            
                break
    return inverse, q
    
def generate_public_key(private_key, parameters=PARAMETERS):
    e_shift = parameters["e_shift"]  
    s_size = parameters["s_size"]
    public_key = []
    inverse, q = private_key
    a = modular_inverse(inverse, q)    
    payload_section = 1 << parameters["s_shift"]
    
    for element_number in range(parameters["dimensions"]):        
        s = random_integer(s_size)
        s |= payload_section
        element = ((a * s) % q) >> e_shift
        public_key.append(element)
    return public_key

def generate_keypair(parameters=PARAMETERS):
    private_key = generate_private_key(parameters)
    public_key = generate_public_key(private_key, parameters)
    return public_key, private_key
    
def public_key_operation(m, public_key, parameters=PARAMETERS):
    ciphertext = 0
    r_cumulative = 0
    r_size = parameters["r_size"]
    for element in public_key[:-1]:
        r = random_integer(r_size)
        r_cumulative += r
        ciphertext += element * r
    r_modulus = parameters["r_modulus"]
    r = (m - r_cumulative) % r_modulus
    assert (r_cumulative + r) % r_modulus == m, ((r_cumulative + r) % r_modulus, m)
    element = public_key[-1]
    ciphertext += (r * element)
    return ciphertext
    
def private_key_operation(ciphertext, private_key, parameters=PARAMETERS):
    inverse, q = private_key
    ciphertext <<= parameters["e_shift"] # decompress
    output = (((ciphertext * inverse) % q) >> parameters["s_shift"]) & parameters["mask"]
    return output
    
def encapsulate_key(public_key, parameters=PARAMETERS):
    key = random_integer(parameters["r_size"])
    ciphertext = public_key_operation(key, public_key, parameters)
    return ciphertext, key
    
def recover_key(ciphertext, private_key, parameters=PARAMETERS):
    return private_key_operation(ciphertext, private_key, parameters)
    
def public_key_encryption(m, public_key, parameters=PARAMETERS):
    return public_key_operation(m, public_key, parameters)
    
def private_key_decryption(ciphertext, private_key, parameters=PARAMETERS):
    return private_key_operation(ciphertext, private_key, parameters)
    
def test_encapsulate_key_recover_key():
    from unittesting import test_key_exchange
    test_key_exchange("uppers2 KEM", generate_keypair, encapsulate_key, recover_key, iterations=10000)
    
def test_public_key_encryption():
    from unittesting import test_asymmetric_encrypt_decrypt
    test_asymmetric_encrypt_decrypt("uppers2 PKE", generate_keypair, public_key_encryption, private_key_decryption, iterations=10000, plaintext_size=SECURITY_LEVEL)
    
if __name__ == "__main__":
    test_encapsulate_key_recover_key()
    test_public_key_encryption()
    