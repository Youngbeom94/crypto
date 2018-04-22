from crypto.utilities import random_integer, modular_inverse, big_prime

SECURITY_LEVEL = 32

def secret_split(m, security_level, shares, modulus):
    shares = [random_integer(security_level) for count in range(shares - 1)]
    shares_product = reduce(lambda x, y: (x * y) % modulus, shares)
    remaining_share = (modular_inverse(shares_product, modulus) * m) % modulus
    shares.append(remaining_share)
    return shares
    
def find_p(security_level=SECURITY_LEVEL):
    from crypto.utilities import is_prime
    p = 2 ** (security_level * 8)
    offset = 1
    while not is_prime(p + offset):
        offset += 2
    return p, offset
    
#P_BASE, OFFSET = find_p(SECURITY_LEVEL)
#print OFFSET
#P = P_BASE + OFFSET    
P = (2 ** (SECURITY_LEVEL * 8)) + 297

def generate_key(security_level=SECURITY_LEVEL, p=P):
    while True:
        k1 = random_integer(32)
        k2 = random_integer(32)
        try:
            k1i = modular_inverse(k1, p - 1)
            k2i = modular_inverse(k2, p - 1)
        except ValueError:
            continue
        else:
            break
    return (k1, k2), (k1i, k2i)
    
def encrypt(m, key, security_level=SECURITY_LEVEL, p=P):
    x, y = secret_split(m, security_level, 2, p)
    k1, k2 = key[0]
    return pow(x, k1, p), pow(y, k2, p)
    
def decrypt(ciphertext, key, p=P, _exp=lambda x, y: pow(x, y, P), _mul=lambda x, y: (x * y) % P):        
    #return reduce(_mul, map(_exp, ciphertext, key[1]))
    c1, c2 = ciphertext
    k1i, k2i = key[1]    
    return (pow(c1, k1i, p) * pow(c2, k2i, p)) % p
    
def multiply(c1, c2, p=P):
    return [(c1[index] * c2[index]) % p for index in range(len(c1))]
    
def exponentiate(c1, c2, p=P):
    # (a * b) ^ (c * d)
    # a^c * a^d * b^c * b^d
    # a^x^(c^x) * a^x^(d^y) * b^y(c^x) * b^y^(d^y)
    # a^(c^x) * a^(d^y) * b^(c^x) * b^(d^y)
    # ab^(c^x) * ab(d^y)
    # ab^(c^x + d^y)    
    
    #a^cd * b^cd
    #ab^cd
    output = []
    for item in c1:
        for item2 in c2:
            output.append(pow(item, item2, p))
    return output
    
def decrypt2(ciphertext, key, p=P):
    c1, c2, c3, c4 = ciphertext
    k1i, k2i = key[1]
    c1 = pow(pow(c1, k1i, p), k1i, p)
    c2 = pow(pow(c2, k1i, p), k2i, p)
    c3 = pow(pow(c3, k2i, p), k1i, p)
    c4 = pow(pow(c4, k2i, p), k2i, p)
    return (c1 * c2 * c3 * c4) % p    
    
def test_encrypt_decrypt():
    from crypto.designs.linear.homomorphic.latticebased.unittesting import test_symmetric_encrypt_decrypt
    #test_symmetric_encrypt_decrypt("a^x, b^y", generate_key, encrypt, decrypt, iterations=10000)
    
    key = generate_key()
    c2 = encrypt(2, key)
    c3 = encrypt(3, key)
    c6 = multiply(c2, c3)    
    assert decrypt(c6, key) == 6
    
    c8 = exponentiate(c2, c3)    
    assert decrypt2(c8, key) == 8, decrypt2(c8, key)
    
if __name__ == "__main__":
    test_encrypt_decrypt()
    