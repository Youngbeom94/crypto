from crypto.utilities import random_integer, secret_split

SECURITY_LEVEL = 32
MODULUS = (2 ** (SECURITY_LEVEL * 8))

def hamming_weight(number): 
    return format(number, 'b').count('1')

def generate_key(security_level=SECURITY_LEVEL):
    return random_integer(security_level)

def encrypt(m, key, security_level=SECURITY_LEVEL, modulus=MODULUS):    
    ciphertext = []
    weight = hamming_weight(key)    
    shares = secret_split(m, security_level, weight, modulus)    
    chaff = [random_integer(security_level) for count in range((security_level * 8) - weight)]    
    for bit_number in range(security_level * 8):
        if (key >> bit_number) & 1 == 1:            
            ciphertext.append(shares.pop(0))
        else:
            ciphertext.append(chaff.pop(0))
    return ciphertext
    
def decrypt(ciphertext, key, security_level=SECURITY_LEVEL, modulus=MODULUS):
    return sum(ciphertext[bit_number] for bit_number in range(security_level * 8) if (key >> bit_number) & 1) % modulus
    
def add(x, y, modulus=MODULUS):
    for index in range(len(x)):        
        x[index] = (x[index] + y[index]) % modulus
            
def mul(x, y, key, modulus=MODULUS):    
    output = [0 for count in range(len(x))]
    for index1 in range(len(x)):
        for index2 in range(len(y)):
            if (key >> index2) & 1:
                output[index1] += (x[index1] * y[index2]) % modulus                 
    return output
            
def test_encrypt_decrypt():
    key = generate_key()
    c0 = encrypt(0, key)
    c1 = encrypt(1, key)
    r = random_integer(SECURITY_LEVEL)
    cr = encrypt(r, key)
    
    p0 = decrypt(c0, key)
    p1 = decrypt(c1, key)
    pr = decrypt(cr, key)
    
    assert p0 == 0
    assert p1 == 1
    assert pr == r
    
    r2 = random_integer(SECURITY_LEVEL)
    cr2 = encrypt(r2, key)
    
    add(cr, cr2)
    assert decrypt(cr, key) == (r + r2) % MODULUS    
            
    cr[:] = mul(cr, cr2, key)        
    assert decrypt(cr, key) == ((r + r2) * r2) % MODULUS
    
    cr[:] = mul(cr, cr, key)
    assert decrypt(cr, key) == (((r + r2) * r2) ** 2) % MODULUS
    
    
if __name__ == "__main__":
    test_encrypt_decrypt()
    
            