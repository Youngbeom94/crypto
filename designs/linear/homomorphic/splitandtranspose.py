# c    f    i         
# +    +    +        
# b    e    h
# +    +    +  --->  shuffle
# a    d    g
# +    +    +
# r0   r1   r2
from crypto.utilities import random_bytes, random_integer, secret_split, shuffle, inverse_shuffle

SECURITY_LEVEL = 32

def generate_private_key(security_level=SECURITY_LEVEL):
    return bytearray(random_bytes(security_level))
    
def generate_public_key(private_key, security_level=SECURITY_LEVEL):
    public_key = []
    modulus = 2 ** (security_level * 8)
    for count in range(32):
        chaff = [random_integer(security_level) for count in range(security_level / 2)]        
        shares_tier0 = secret_split(0, security_level, 4, modulus)
        shares = []
        for share in shares_tier0:
            shares.extend(secret_split(share, security_level, 4, modulus))
        assert len(shares) == 16
        combined = shares + chaff
        shuffle(combined, private_key)
        for chaff_share in chaff:
            if combined[0] == chaff_share:
                raise ValueError("Invalid private key")
        public_key.append(combined)
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
    for count in range(16):
        selection = random_integer(1) & 31
        element = public_key[selection]
        add_element(ciphertext, element)
    ciphertext[0] += m
    return ciphertext
    
def decrypt(ciphertext, private_key, security_level=SECURITY_LEVEL):
    inverse_shuffle(ciphertext, private_key)
    modulus = 2 ** (security_level * 8)
    return sum(ciphertext[:16]) % modulus
    
def test_encrypt_decrypt():
    while True:
        try:
            public, private = generate_keypair()
        except ValueError:
            continue
        else:
            break
    c0 = encrypt(0, public)
    p0 = decrypt(c0, private)
    assert p0 == 0
    print sum(encrypt(0, public)) % (2 ** 256)
    print
    print sum(encrypt(0, public)) % (2 ** 256)
    
    
    c1 = encrypt(1, public)
    p1 = decrypt(c1, private)
    assert p1 == 1
    
    r = random_integer(32)
    cr = encrypt(r, public)
    pr = decrypt(cr, private)
    
    assert pr == r, (pr, r)
    print("Unit test passed")
    
if __name__ == "__main__":
    test_encrypt_decrypt()
    
    
    