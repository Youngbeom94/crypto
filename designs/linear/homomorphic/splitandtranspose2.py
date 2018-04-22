from crypto.utilities import random_integer, secret_split, hamming_weight

SECURITY_LEVEL = 32

def generate_private_key(security_level=SECURITY_LEVEL):
    return random_integer(security_level) | 1
    
def generate_public_key(private_key, security_level=SECURITY_LEVEL):
    public_key = []
    modulus = 2 ** (security_level * 8)        
       
    for public_key_element_number in range(security_level * 8):
        element = []        
        shares = secret_split(0, security_level, hamming_weight(private_key), modulus)        
        for counter in range(security_level * 8):
            if (private_key >> counter) & 1:
                element.append(shares.pop(0))
            else:
                element.append(random_integer(security_level))
        public_key.append(element)
    return public_key       
    
def generate_keypair(security_level=SECURITY_LEVEL):
    private_key = generate_private_key(security_level)    
    public_key = generate_public_key(private_key, security_level)    
    return public_key, private_key
    
def add_element(list1, list2):
    for index in range(len(list1)):
        list1[index] += list2[index]
    #return [list1[index] + list2[index] for index in range(len(list1))]
    
def encrypt(m, public_key, security_level=SECURITY_LEVEL):
    ciphertext = [0 for count in range(len(public_key[0]))]
    selection_size = security_level * 8
    integer_size = max(security_level / 256, 1)
    
    for count in range(selection_size / 2):
        selection = random_integer(integer_size) % selection_size    
        element = public_key[selection]
        add_element(ciphertext, element)
    ciphertext[0] += m
    return ciphertext
    
def decrypt(ciphertext, private_key, security_level=SECURITY_LEVEL):
    message = 0
    for counter in range(security_level * 8):
        if (private_key >> counter) & 1:
            message += ciphertext[counter]
            
    modulus = 2 ** (security_level * 8)
    return message % modulus
    
def test_encrypt_decrypt():
    public, private = generate_keypair()
    modulus = 2 ** (SECURITY_LEVEL * 8)
    c0 = encrypt(0, public)
    p0 = decrypt(c0, private)
    assert p0 == 0
                
    c1 = encrypt(1, public)
    p1 = decrypt(c1, private)
    assert p1 == 1
    
    r = random_integer(SECURITY_LEVEL)
    cr = encrypt(r, public)
    pr = decrypt(cr, private)
    
    assert pr == r, (pr, r)
    #print("Unit test passed")
    from crypto.designs.linear.homomorphic.latticebased.unittesting import test_asymmetric_encrypt_decrypt
    test_asymmetric_encrypt_decrypt("split and transpose 2", generate_keypair, encrypt, decrypt, iterations=100, plaintext_size=SECURITY_LEVEL)
    
if __name__ == "__main__":
    test_encrypt_decrypt()
    