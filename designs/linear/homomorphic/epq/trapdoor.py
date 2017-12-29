from crypto.utilities import modular_inverse, random_integer

SECURITY_LEVEL = 32
PADDING = 4

def generate_parameter_sizes(security_level=SECURITY_LEVEL, padding=PADDING):
    q_size = security_level * 20
        
    inverse_size = security_level 
    shift = security_level * 8
    k_size = security_level * 15
    a_shift = security_level * 14 * 8
    
    s_size = security_level * 3
    e_shift = ((security_level * 18) * 8) - (padding * 8)
    
    mask = (2 ** (security_level * 8)) - 1
    return q_size, inverse_size, shift, k_size, a_shift, s_size, e_shift, mask
    
Q_SIZE, INVERSE_SIZE, SHIFT, K_SIZE, A_SHIFT, S_SIZE, E_SHIFT, MASK = generate_parameter_sizes(SECURITY_LEVEL, PADDING)
Q = 2 ** (Q_SIZE * 8)
print Q_SIZE, INVERSE_SIZE, A_SHIFT, E_SHIFT

def generate_private_key(inverse_size=INVERSE_SIZE, k_size=K_SIZE, q=Q, shift=SHIFT):
    """ usage: generate_private_key(inverse_size=INVERSE_SIZE, q_size=Q_SIZE) => private_key
        
        Returns the integer(s) that constitute a private key. """
    while True:
        inverse = random_integer(inverse_size) << shift
        k = random_integer(k_size)
        try:
            modular_inverse(inverse, q + k)
        except ValueError:
            continue
        else:
            break            
    return inverse, q + k
    
def generate_public_key(private_key, q=Q, a_shift=A_SHIFT):
    """ usage: generate_public_key(private_key, q=Q, k_size=K_SIZE) => public_key
        
        Returns the integer that constitutes a public key. """
    ai, q_k = private_key    
    a = modular_inverse(ai, q_k)
    return (a >> a_shift) << a_shift
    
def generate_keypair(inverse_size=INVERSE_SIZE, k_size=K_SIZE, q=Q, shift=SHIFT):
    """ usage: generate_keypair(invers_size=INVERSE_SIZE, 
                                q_size=Q_SIZE, k_size=K_SIZE) => public_key, private_key
                                
        Returns a public key and a private key. """    
    private_key = generate_private_key(inverse_size, k_size, q, shift)
    public_key = generate_public_key(private_key, q)
    return public_key, private_key
    
def public_key_operation(public_key, s, e_shift=E_SHIFT, q=Q, mask=MASK):
    """ usage: encapsulate_key(public_key, s_size=S_SIZE, e_shift=E_SHIFT) => ciphertext, key
    
        Returns a ciphertext integer. """        
    return ((public_key * s) % q) >> e_shift
    
def private_key_operation(ciphertext, private_key, q=Q, e_shift=E_SHIFT, mask=MASK):
    """ usage: recover_key(ciphertext, private_key) => plaintext value
        
        Returns the integer that constitutes a plaintext value. """
    ai, q_k = private_key
    return (((ciphertext << e_shift) * ai) % (q_k)) & mask
   