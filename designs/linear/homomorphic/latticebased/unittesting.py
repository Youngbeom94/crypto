from timeit import default_timer

from crypto.utilities import random_integer, size_in_bits, random_bytes

class UnitTestFailure(BaseException): pass


def test_for_homomorphism(ciphertext1, ciphertext2, decrypt, key, m1, m2):    
    try:
        if decrypt(ciphertext1 + ciphertext2, key) == m1 + m2:
            print("Ciphertexts support addition: D(E(m1) + E(m2)) == m1 + m2")        
    except (TypeError, ValueError):
        pass
        
    try:
        if decrypt(ciphertext1 * ciphertext2, key, depth=2) == m1 * m2:
            print("Ciphertexts support multiplication: D(E(m1) * E(m2)) == m1 * m2")
    except TypeError:
        try:
            if decrypt(ciphertext1 * ciphertext2, key) == m1 * m2:
                print("Ciphertexts support multiplication: D(E(m1) * E(m2)) == m1 * m2") 
        except TypeError:
            pass
    try:
        if decrypt(ciphertext1 ^ ciphertext2, key) == m1 ^ m2:
            print("Ciphertexts support XOR: D(E(m1) ^ E(m2)) == m1 ^ m2")
    except TypeError:
        pass
    
    try:
        if decrypt(ciphertext1 & ciphertext2, key) == m1 & m2:
            print("Ciphertexts support AND: D(E(m1) & E(m2)) == m1 & m2")
    except TypeError:
        pass
        
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
                try:
                    sizes.append(size_in_bits(item))    
                except TypeError:
                    for _item in item:
                        for __item in _item:
                            sizes.append(size_in_bits(__item))
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
    ciphertext_size = determine_key_size(ciphertext)
    
    print("Public key size : {}".format(sum(public_sizes)))
    print("Private key size: {}".format(sum(private_sizes)))
    print("Ciphertext size : {}".format(sum(ciphertext_size)))
    print("(sizes are in bits)")
    print("{} unit test passed".format(algorithm_name))
       
def test_symmetric_encrypt_decrypt(algorithm_name, generate_key, encrypt, decrypt,
                                   iterations=1024, plaintext_size=32):
    print("Beginning {} unit test...".format(algorithm_name))
    print("Validating correctness...")
    for count in range(iterations):
        key = generate_key()
        message = random_integer(plaintext_size)
        ciphertext = encrypt(message, key)
        plaintext = decrypt(ciphertext, key)
        if plaintext != message:
            raise UnitTestFailure("Unit test failed after {} successful tests".format(count))
    print("...done")
        
    test_encrypt_decrypt_time(iterations, encrypt, decrypt, key, key, plaintext_size)
        
    m1 = 10
    m2 = 20
    c1 = encrypt(m1, key)
    c2 = encrypt(m2, key)
    test_for_homomorphism(c1, c2, decrypt, key, m1, m2)
      
    key_size = determine_key_size(key) 
    ciphertext_size = determine_key_size(c1)
    print("Key size: {}".format(sum(key_size)))
    print("Ciphertext size: {}".format(sum(ciphertext_size)))
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
    ciphertext_size = determine_key_size(ciphertext)
    print("Public key size : {}".format(sum(public_sizes)))
    print("Private key size: {}".format(sum(private_sizes)))
    print("Ciphertext size : {}".format(sum(ciphertext_size)))
    print("(sizes are in bits)")
    print("{} unit test passed".format(algorithm_name))
    
def test_sign_verify_time(iterations, sign, verify, public_key, private_key, message_size=32, random_generator=random_integer):    
    message = random_generator(message_size)
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
    
    message = random_integer(message_size)
    random_generator = random_integer
    try:
        sign(message, private_key)
    except TypeError:
        message = random_bytes(message_size)
        try:
            sign(message, private_key)
        except TypeError:
            raise TypeError("Unable to determine type of message to be signed")
        else:
            random_generator = random_bytes
            
    print("Validating correctness...")
    for count in range(iterations):
        message = random_generator(message_size)
        signature = sign(message, private_key)
        if not verify(signature, message, public_key):        
            raise UnitTestFailure("Unit test failed after {} successful signature verifications".format(count))
    print("...done")
    
    test_sign_verify_time(iterations, sign, verify, public_key, private_key, message_size, random_generator)
    
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
    