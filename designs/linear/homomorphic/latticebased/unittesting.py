from timeit import default_timer

from crypto.utilities import random_integer, size_in_bits

class UnitTestFailure(BaseException): pass


def test_for_homomorphism(ciphertext1, ciphertext2, decrypt, key, m1, m2):    
    if decrypt(ciphertext1 + ciphertext2, key) == m1 + m2:
        print("Ciphertexts support addition: D(E(m1) + E(m2)) == m1 + m2")        
        
    try:
        if decrypt(ciphertext1 * ciphertext2, key, depth=2) == m1 * m2:
            print("Ciphertexts support multiplication: D(E(m1) * E(m2)) == m1 * m2")
    except TypeError:
        if decrypt(ciphertext1 * ciphertext2, key) == m1 * m2:
            print("Ciphertexts support multiplication: D(E(m1) * E(m2)) == m1 * m2") 
            
    if decrypt(ciphertext1 ^ ciphertext2, key) == m1 ^ m2:
        print("Ciphertexts support XOR: D(E(m1) ^ E(m2)) == m1 ^ m2")
    if decrypt(ciphertext1 & ciphertext2, key) == m1 & m2:
        print("Ciphertexts support AND: D(E(m1) & E(m2)) == m1 & m2")
        
def determine_key_size(key):    
    sizes = []
    try:
        sizes.append(size_in_bits(key))
    except TypeError:        
        for item in key:
            try:
                for _item in item:
                    sizes.append(size_in_bits(_item))
            except TypeError:
                sizes.append(size_in_bits(item))    
    return sizes
    
def test_encrypt_decrypt_time(iterations, encrypt, decrypt, public_key, private_key, plaintext_size):  
    print("Beginning encrypt/decrypt time test")
    print("Encrypting {} {}-byte messages...".format(iterations, plaintext_size))    
    message = int('11111111' * plaintext_size, 2)
    
    before = default_timer()
    for count in range(iterations):                         
        ciphertext = encrypt(message, public_key)                
    after = default_timer()
    print("Time required: {}".format(after - before))
    
    print("Decrypting {} {}-byte messages...".format(iterations, plaintext_size))
    before = default_timer()
    for count in range(iterations):
        plaintext = decrypt(ciphertext, private_key)       
    after = default_timer()
    print("Time required: {}".format(after - before))
            
def test_asymmetric_encrypt_decrypt(algorithm_name, generate_keypair, encrypt, decrypt,
                                    iterations=1024, plaintext_size=32):    
    print("Beginning {} unit test".format(algorithm_name))           
    print("Validating correctness...")
    for count in range(iterations):
        public_key, private_key = generate_keypair()
        message = random_integer(plaintext_size)
        ciphertext = encrypt(message, public_key)
        plaintext = decrypt(ciphertext, private_key)
        if plaintext != message:
            raise UnitTestFailure("Unit test failed after {} successful tests".format(count))
    print("...done")
    
    test_encrypt_decrypt_time(iterations, encrypt, decrypt, public_key, private_key, plaintext_size)
    
    m1, m2 = 3, 6
    ciphertext1 = encrypt(m1, public_key)
    ciphertext2 = encrypt(m2, public_key)    
    test_for_homomorphism(ciphertext1, ciphertext2, decrypt, private_key, m1, m2)
        
    public_sizes = determine_key_size(public_key)
    private_sizes = determine_key_size(private_key)
            
    print("Public key size : {}".format(sum(public_sizes)))
    print("Private key size: {}".format(sum(private_sizes)))
    print("Ciphertext size : {}".format(size_in_bits(encrypt(random_integer(plaintext_size), public_key))))
    print("(sizes are in bits)")
    print("{} unit test passed".format(algorithm_name))
       
def test_symmetric_encrypt_decrypt(algorithm_name, generate_key, encrypt, decrypt,
                                   iterations=1024, plaintext_size=32):
    print("Beginning {} unit test...".format(algorithm_name))
    print("Generating key...")
    key = generate_key()
    print("...done")
    
    test_encrypt_decrypt_time(iterations, encrypt, decrypt, key, key, plaintext_size)
        
    m1 = 10
    m2 = 20
    c1 = encrypt(m1, key)
    c2 = encrypt(m2, key)
    test_for_homomorphism(c1, c2, decrypt, key, m1, m2)
      
    key_size = determine_key_size(key)          
    print("Key size: {}".format(sum(key_size)))
    print("Ciphertext size: {}".format(size_in_bits(encrypt(random_integer(plaintext_size), key))))
    print("{} unit test passed".format(algorithm_name))

def test_exchange_key_recover_key_time(iterations, exchange_key, recover_key, public_key, private_key, key_size=32):        
    if iterations == 0:
        return None    
    print("Exchanging {} {}-byte keys...".format(iterations, key_size))            
    before = default_timer()
    for count in range(iterations):                     
        ciphertext, key = exchange_key(public_key)
    after = default_timer()
    print("Time required: {}".format(after - before))
    
    print("Recovering {} {}-byte keys...".format(iterations, key_size))
    before = default_timer()
    for count in range(iterations):
        _key = recover_key(ciphertext, private_key)       
    after = default_timer()
    print("Time required: {}".format(after - before))        
    
def test_key_exchange(algorithm_name, generate_keypair, exchange_key, recover_key, 
                      iterations=1024, key_size=32):
    print("Beginning {} unit test...".format(algorithm_name))
    #print("Generating keypair...")
    #
    #print("...done")
    
    print("Validating correctness...")
    for count in range(iterations):
        public_key, private_key = generate_keypair()
        ciphertext, key = exchange_key(public_key)
        assert ciphertext != 0
        assert key != 0
        _key = recover_key(ciphertext, private_key)
        if _key != key:
            raise UnitTestFailure("Unit test failed (after {} successful exchanges)".format(count))
    print("...done")
    
    test_exchange_key_recover_key_time(iterations, exchange_key, recover_key, public_key, private_key, key_size)
    
    public_sizes = determine_key_size(public_key)
    private_sizes = determine_key_size(private_key)
    print("Public key size : {}".format(sum(public_sizes)))
    print("Private key size: {}".format(sum(private_sizes)))
    print("Ciphertext size : {}".format(size_in_bits(exchange_key(public_key)[0])))
    print("(sizes are in bits)")
    print("{} unit test passed".format(algorithm_name))
    
def test_sign_verify_time(iterations, sign, verify, public_key, private_key, message_size=32):    
    message = random_integer(message_size)
    print("Signing {} {}-bit messages...".format(iterations, message_size * 8))         
    before = default_timer()
    for count in range(iterations):                     
        signature = sign(message, private_key)
    after = default_timer()
    print("Time required: {}".format(after - before))
    
    print("Verifying {} {}-bit signatures...".format(iterations, sum(determine_key_size(signature))))
    before = default_timer()
    for count in range(iterations):
        valid_flag = verify(signature, message, public_key)       
    after = default_timer()
    print("Time required: {}".format(after - before))        
    
def test_sign_verify(algorithm_name, generate_keypair, sign, verify, 
                     iterations=1024, message_size=32):
    print("Beginning {} unit test...".format(algorithm_name))
    print("Generating keypair...")
    public_key, private_key = generate_keypair()
    print("...done")
    
    print("Validating correctness...")
    for count in range(iterations):
        message = random_integer(message_size)
        signature = sign(message, private_key)
        if not verify(signature, message, public_key):        
            raise UnitTestFailure("Unit test failed after {} successful signature verifications".format(count))
    print("...done")
    
    test_sign_verify_time(iterations, sign, verify, public_key, private_key, message_size)
    
    public_sizes = determine_key_size(public_key)
    private_sizes = determine_key_size(private_key)
    print("Public key size : {}".format(sum(public_sizes)))
    print("Private key size: {}".format(sum(private_sizes)))
    print("Signature size : {}".format(sum(determine_key_size(signature))))
    print("(sizes are in bits)")
    print("{} unit test passed".format(algorithm_name))    
    
def test_key_agreement_time(iterations, key_agreement, generate_keypair, key_size=32):        
    if iterations == 0:
        return None    
    print("Agreeing upon {} {}-byte keys...".format(iterations, key_size))                
    before = default_timer()
    for count in range(iterations):                     
        public_key, private_key = generate_keypair()
        key = key_agreement(public_key, private_key)
    after = default_timer()
    print("Time required: {}".format(after - before))   
    
def test_key_agreement(algorithm_name, generate_keypair, key_agreement, 
                       iterations=1024, key_size=32):
    print("Beginning {} unit test...".format(algorithm_name))
    #print("Generating {} keypairs...".format(iterations))    
    #before = default_timer()
    #for count in range(iterations):
    #    public_key, private_key = generate_keypair()        
    #after = default_timer()
    #print("...done")
    #print("Time required: {}".format(after - before))
               
    print("Validating correctness...")    
    for count in range(iterations):
        public_key, private_key = generate_keypair()
        public_key2, private_key2 = generate_keypair()
        key = key_agreement(public_key2, private_key)
        _key = key_agreement(public_key, private_key2)
        assert key and key == _key, (count, key, _key)
    print("...done")
    
    test_key_agreement_time(iterations, key_agreement, generate_keypair, key_size=key_size)
    
    public_sizes = determine_key_size(public_key)
    private_sizes = determine_key_size(private_key)
    print("Public key size : {}".format(sum(public_sizes)))
    print("Private key size: {}".format(sum(private_sizes)))
    print("Key size : {}".format(sum(determine_key_size(key))))
    print("(sizes are in bits)")
    print("{} unit test passed".format(algorithm_name))
    