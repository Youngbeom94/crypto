# ax + by + cz
# ai(by + cz) + x
# bi(ax + cz) + y
# ci(ax + by) + z


from crypto.utilities import random_integer

import secretkey

Q = secretkey.Q
R_SIZE = 32

def generate_private_key(inverse_size=secretkey.INVERSE_SIZE, q=Q, generate_secret_key=secretkey.generate_secret_key):
    return generate_secret_key(inverse_size, q)
    
def generate_public_key(private_key, s_size=secretkey.S_SIZE, s_shift=secretkey.S_SHIFT, e_size=secretkey.E_SIZE,
                        q=Q, encrypt=secretkey.encrypt): 
    return encrypt(1, private_key, s_size, s_shift, e_size, q)
    
def multiparty_key_agreement(public_keys, r_size=R_SIZE, q=Q):
    ciphertext = 0
    shares = []
    for public_key in public_keys:
        shared_secret = random_integer(r_size)
        ciphertext += public_key * shared_secret
        shares.append(shared_secret)
    return ciphertext, shares
    
def recover_key(ciphertext, private_key, s_mask=secretkey.S_MASK, q=Q, decrypt=secretkey.decrypt):
    return decrypt(ciphertext private_key, s_mask, q)
    
    