# a b c d e f g h, p q, N = pq
# public key operation: random subset product of elements mod N
# private key operation: modular_inverse(ciphertext, p); if ciphertext % element, ciphertext /= element
from crypto.utilities import random_integer, big_prime, modular_inverse

SECURITY_LEVEL = 8
DIMENSION = 8

def generate_parameter_sizes(security_level=SECURITY_LEVEL, dimension=DIMENSION):
    prime_size = (security_level * dimension) + 1
        
def generate_private_key(security_level=SECURITY_LEVEL, dimension=DIMENSION):    
    prime_size = (security_level * dimension) + 1
    p = big_prime(prime_size)
    q = big_prime(prime_size)
        
    elements = []
    check_value = 1
    for element_number in range(dimension):
        element = random_integer(security_level)
        elements.append(element)
        check_value *= element
    assert check_value < p
    return sorted(elements), p, q
    
def generate_public_key(private_key):
    elements, p, q = private_key
    public_elements = [modular_inverse(element, p) for element in elements]
    n = p * q
    return public_elements, n
    
def generate_keypair(security_level=SECURITY_LEVEL, dimension=DIMENSION):
    private_key = generate_private_key(security_level, dimension)
    public_key = generate_public_key(private_key)
    return public_key, private_key
    
def public_key_operation(public_key, dimension=DIMENSION):
    elements, n = public_key
    mask = dimension - 1
    ciphertext = 1
    secret = []
    for counter in range(dimension):
        selection = random_integer(1) & mask
        ciphertext *= elements[selection]
        secret.append(selection)
    ciphertext %= n
    return ciphertext, sorted(secret)
    
def private_key_operation(ciphertext, private_key):
    secret = []
    elements, p, q = private_key
    ciphertext = modular_inverse(ciphertext, p)
    for index, element in enumerate(elements):
        while ciphertext % element == 0:            
            secret.append(index)
            ciphertext /= element
    return secret
    
def test_public_key_operation_private_key_operation():
    public_key, private_key = generate_keypair()
    ciphertext, secret = public_key_operation(public_key)
    _secret = private_key_operation(ciphertext, private_key)
    assert secret == _secret, (secret, _secret)
        
if __name__ == "__main__":
    test_public_key_operation_private_key_operation()
    