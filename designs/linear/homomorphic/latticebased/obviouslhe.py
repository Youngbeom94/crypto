#broken
# c = (km mod qx) + qy
# m = ki c mod q
from crypto.utilities import random_integer, modular_inverse

SECURITY_LEVEL = 32

def generate_parameter_sizes(security_level=SECURITY_LEVEL):
    k_size = security_level
    q_size = security_level
    m_size = q_size    
    x_size = security_level
    return k_size, q_size, m_size, x_size
    
K_SIZE, Q_SIZE, M_SIZE, X_SIZE = generate_parameter_sizes(SECURITY_LEVEL)

def generate_secret_key(k_size=K_SIZE, q_size=Q_SIZE):
    while True:
        k = random_integer(k_size)
        q = random_integer(q_size)
        try:
            ki = modular_inverse(k, q)
        except ValueError:
            continue
        else:
            if k > q:
                k, q = q, k
            break
    return k, ki, q
    
def encrypt(m, key, x_size=X_SIZE):
    if m == 0:
        raise ValueError("Insecure m == 0")
    x = random_integer(x_size)
    y = random_integer(x_size)
    r = random_integer(x_size * 2)
    k, ki, q = key
    while True:
        try:
            k_r = modular_inverse(ki, q * r)            
        except ValueError:
            r += 1
            continue
        else:
            c = ((k_r * m) % (q * x)) + (q * y)
            break
    return c
    
def decrypt(c, key, depth=1):
    k, ki, q = key
    return (c * pow(ki, depth, q)) % q
                
def unit_test():
    from unittesting import test_symmetric_encrypt_decrypt
    test_symmetric_encrypt_decrypt("obviouslhe", generate_secret_key, encrypt, decrypt, iterations=10000)
    
if __name__ == "__main__":
    unit_test()
    