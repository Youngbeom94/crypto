import struct
import itertools
import random
import binascii
from operator import xor as _operator_xor
from fractions import gcd
from os import urandom as random_bytes
from math import log

def slide(iterable, x=16):
    """ Yields x bytes at a time from iterable """
    slice_count, remainder = divmod(len(iterable), x)
    for position in range((slice_count + 1 if remainder else slice_count)):
        _position = position * x
        yield iterable[_position:_position + x]         
    
def null_pad(seed, size):
    return bytearray(seed + ("\x00" * (size - len(seed))))
    
def xor_parity(data):
    bits = [int(bit) for bit in cast(bytes(data), "binary")]
    parity = bits[0]
    for bit in bits[1:]:
        parity ^= bit
    return parity

def xor_sum(data):
    _xor_sum = 0
    for byte in data:
        _xor_sum ^= byte
    return _xor_sum
    
def rotate(input_string, amount):
    if not amount or not input_string:            
        return input_string    
    else:
        amount = amount % len(input_string)
        return input_string[-amount:] + input_string[:-amount]                

def rotate_right(x, r, bit_width=8, _mask=dict((bit_width, ((2 ** bit_width) - 1)) for bit_width in (2, 4, 8, 16, 32, 64, 128))): 
    r %= bit_width
    return ((x >> r) | (x << (bit_width - r))) & _mask[bit_width]
    
def rotate_left(x, r, bit_width=8, _mask=dict((bit_width, ((2 ** bit_width) - 1)) for bit_width in (2, 4, 8, 16, 32, 64, 128))):  
    r %= bit_width
    return ((x << r) | (x >> (bit_width - r))) & _mask[bit_width]
    
def shift_left(byte, amount, bit_width=8):
    return (byte << amount) & ((2 ** bit_width) - 1)   
    
def shift_right(byte, amount, bit_width=8):
    return (byte >> amount) & ((2 ** bit_width) - 1)
        
def xor_subroutine(bytearray1, bytearray2): 
    size = min(len(bytearray1), len(bytearray2))    
    for index in range(size):
        bytearray1[index] ^= bytearray2[index]
               
def replacement_subroutine(bytearray1, bytearray2): 
    size = min(len(bytearray1), len(bytearray2))
    for index in range(size):
        bytearray1[index] = bytearray2[index]
        
    #for index, byte in enumerate(bytearray2):
    #    bytearray1[index] = byte
        
def binary_form(_string):
    """ Returns the a string representation of the binary bits that constitute _string. """
    try:
        return ''.join(format(ord(character), 'b').zfill(8) for character in _string)
    except TypeError:        
        if isinstance(_string, bytearray):
            raise
        bits = format(_string, 'b')
        bit_length = len(bits)
        if bit_length % 8:
            bits = bits.zfill(bit_length + (8 - (bit_length % 8)))                
        return bits
        
def byte_form(bitstring):
    """ Returns the ascii equivalent string of a string of bits. """
    try:
        _hex = hex(int(bitstring, 2))[2:]
    except TypeError:
        _hex = hex(bitstring)[2:]
        bitstring = binary_form(bitstring)
    try:
        output = binascii.unhexlify(_hex[:-1 if _hex[-1] == 'L' else None])
    except TypeError:
        output = binascii.unhexlify('0' + _hex[:-1 if _hex[-1] == 'L' else None])
        
    if len(output) == len(bitstring) / 8:
        return output
    else:
        return ''.join(chr(int(bits, 2)) for bits in slide(bitstring, 8))
      
def integer_form(_string):
    return int(binary_form(_string), 2)
        
_type_resolver = {"bytes" : byte_form, "binary" : binary_form, "integer" : lambda bits: int(bits, 2)}
    
def cast(input_data, _type):
    return _type_resolver[_type](input_data)
    
def hamming_weight(word):
    return format(word, 'b').count('1')
    # from http://stackoverflow.com/a/109025/3103584
    # "you are not meant to understand or maintain this code, just worship the gods that revealed it to mankind. I am not one of them, just a prophet"
    #word32 = word32 - ((word32 >> 1) & 0x55555555)
    #word32 = (word32 & 0x33333333) + ((word32 >> 2) & 0x33333333)
    #return (((word32 + (word32 >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24    
    
def generate_s_box(function):
    S_BOX = bytearray(256)
    for number in range(256):    
        S_BOX[number] = function(number)        
    return S_BOX    
    
def find_cycle_length(function, *args, **kwargs):
    args = list(args)
    _input = args[0]    
    outputs = [_input]            
    while True:                        
        args[0] = function(*args, **kwargs)         
        if args[0] in outputs:            
            break
        else:
            outputs.append(args[0])
    return outputs

def find_cycle_length_subroutine(function, data, output_size=1, *args, **kwargs):       
    outputs = [data[:1]]            
    while True:                        
        function(data, *args, **kwargs)         
        if data[:output_size] in outputs:            
            break
        else:
            outputs.append(data[:output_size])
    return outputs
    
def find_long_cycle_length(max_size, chunk_size, function, _input, *args, **kwargs):
    outputs = set([bytes(_input)])
 
    blocks, extra = divmod(max_size, chunk_size)
    exit_flag = False
    for block in xrange(blocks if not extra else blocks + 1):        
        for counter in xrange(chunk_size):                           
            _input = bytes(function(bytearray(_input), *args, **kwargs))          
            if _input in outputs:  
                exit_flag = True
                break
            else:
                outputs.add(_input)
        if exit_flag:
            break                
        yield block * chunk_size

    yield outputs
    
def find_long_cycle_length_subroutine(max_size, chunk_size, function, _input, *args, **kwargs):
    data_size = kwargs.pop("data_slice", slice(0, 3))
    outputs = set()
    outputs.add(tuple(_input[data_size]))
    
    blocks, extra = divmod(max_size, chunk_size)
    exit_flag = False
    for block in xrange(blocks if not extra else blocks + 1):        
        for counter in xrange(chunk_size):                           
            function(_input, *args, **kwargs)
            output = tuple(_input[data_size])
            if output in outputs:  
                exit_flag = True
                break
            else:
                outputs.add(output)
        if exit_flag:
            break                
        yield block * chunk_size

    yield outputs
    
def random_oracle_hash_function(input_data, memo={}):
    try:
        return memo[input_data]
    except KeyError:
        result = memo[input_data] = random_bytes(32)
        return result
        
def generate_key(size, wordsize=8):
    key_material = binary_form(random_bytes(size))
    if wordsize == 8:
        result = key_material
    else:
        result = [int(word, 2) for word in slide(key_material, wordsize)] 
    return result
    
def pad_input(hash_input, size):        
    hash_input += chr(128)
    input_size = len(hash_input) + 8 # + 8 for 64 bits for the size bytes at the end
    padding = size - (input_size % size)
    hash_input += ("\x00" * padding) + (struct.pack("Q", input_size)) 
    assert not len(hash_input) % size, (len(hash_input), size)
    return hash_input
    
def bytes_to_words(seed, wordsize):
    state = []
    seed_size = len(seed)
    for offset in range(seed_size / wordsize):        
        byte = 0
        offset *= wordsize
        for index in range(wordsize):        
            byte |= seed[offset + index] << (8 * index)
        state.append(byte)
    return state
    
def words_to_bytes(state, wordsize):        
    output = bytearray()
    storage = list(state)
    while storage:
        byte = storage.pop(0)
        for amount in range(wordsize):
            output.append((byte >> (8 * amount)) & 255)
    return output
    
def bytes_to_integer(data):
    output = 0    
    size = len(data)
    for index in range(size):
        output |= data[index] << (8 * (size - 1 - index))
    return output
    
def random_integer(size_in_bytes):
    return bytes_to_integer(bytearray(random_bytes(size_in_bytes)))
    
def integer_to_bytes(integer, _bytes):
    output = bytearray()
    #_bytes /= 2
    for byte in range(_bytes):        
        output.append((integer >> (8 * (_bytes - 1 - byte))) & 255)
    return output
    
def high_order_byte(byte, wordsize=8):
    bits = (wordsize / 2) * 8
    mask = ((2 ** bits) - 1) << bits
    return (byte & mask) >> bits
    
def low_order_byte(byte, wordsize=8):
    bits = (wordsize / 2) * 8    
    return (byte & ((2 ** bits) - 1))
    
def modular_addition(x, y, modulus=256):
    return (x + y) % modulus
    
def modular_subtraction(x, y, modulus=256):
    return (modulus + (x - y)) % modulus

def print_state_4x4(state, message=''):
    if message:
        print message    
    for word in slide(state, 4):
        print ' '.join(format(byte, 'b').zfill(8) for byte in word)
        print
            
def brute_force(output, function, test_bytes, prefix='', postfix='', joiner='',
                string_slice=None):
    """ usage: brute_force(output, function, test_bytes, 
                           prefix='', postfix='', 
                           joiner='') => input where function(input) == output
                           
        Attempt to find an input for function that produces output.
            - test_bytes should be an iterable of iterables which containing the symbols that 
              are to be tested 
                - i.e. [ASCII, ASCII], ['0123456789', 'abcdef']
                - symbols can be strings of any size
                    - [my_password_dictionary, my_password_dictionary], 
                        - my_password_dictionary can be an iterable of common words
            - prefix and postfix are any constant strings to prepend/append to each attempted input
            - joiner is the symbol to use when joining symbols for a test input
                - use '' (default) for test_bytes like [ASCII, ASCII]
                - use ' ' to test word lists [dictionary, dictionary]
                    - or have the word lists themselves include relevant spacing/punctuation
        Raises ValueError if no input was found that produces output."""  
    string_slice = slice(0, None) if string_slice is None else string_slice
    for permutation in itertools.product(*test_bytes):              
        if function(prefix + joiner.join(permutation) + postfix)[string_slice] == output[string_slice]:            
            return prefix + joiner.join(permutation) + postfix
    else:                   
        raise ValueError("Unable to recover input for given output with supplied arguments")  
        
def bytes_to_longs(data):
    return [bytes_to_integer(word) for word in slide(data, 4)]          
    
def longs_to_bytes(*longs):
    output = bytearray()
    for long in longs:
        output.extend(integer_to_bytes(long, 4))
    return output
    
def bytes_to_long_longs(data):
    return [bytes_to_integer(word) for word in slide(data, 8)]          
    
def long_longs_to_bytes(*longs):
    output = bytearray()
    for long in longs:
        output.extend(integer_to_bytes(long, 8))
    return output
    
def shuffle(data, key):
    for i in reversed(range(1, len(data))):
        # Fisher-Yates shuffle        
        j = key[i] % i  # biased
        data[i], data[j] = data[j], data[i]           
            
def inverse_shuffle(data, key):
    for i in range(1, len(data)):
        j = key[i] % i
        data[i], data[j] = data[j], data[i]
        
def choice(a, b, c):
    return c ^ (a & (b ^ c))
    
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modular_inverse(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError('modular inverse does not exist')
    else:
        return x % m
        
def multiplication_subroutine(data1, data2, modulus):    
    amount = min(len(data1), len(data2))
    for index in range(amount):
        data1[index] = (data1[index] * data2[index]) % modulus
    
def addition_subroutine(data1, data2, modulus):    
    size = min(len(data1), len(data2))    
    for index in range(size):
        data1[index] = (data1[index] + data2[index]) % modulus
        
#def addition_subroutine(data1, data2, modulus): 
#    data1[:] = ((byte + next(data2)) % modulus for byte in data1)
#    
#def multiplication_subroutine(data1, data2, modulus):
#    data1[:] = ((byte * next(data2)) % modulus for byte in data1)
    
def subtraction_subroutine(data1, data2, modulus):
    size = min(len(data1), len(data2))
    for index in range(size):
        data1[index] = modular_subtraction(data1[index], data2[index], modulus) 
        
def prime_generator():
    filter = set([2, 3, 5])
    yield 2
    yield 3
    yield 5
    for number in itertools.count(6):
        for prime in filter:
            if not number % prime:
                break
        else:
            yield number
            filter.add(number)
          
def odd_size_to_bytes(hash_output, word_size): 
    bits = ''.join(format(word, 'b').zfill(word_size) for word in hash_output)
    return bytearray(int(_bits, 2) for _bits in slide(bits, 8))
                  
def integer_to_words(integer, integer_size_bits, word_size_bits):
    assert integer_size_bits >= word_size_bits
    output_words, extra = divmod(integer_size_bits, word_size_bits)
    if extra:
        output_words += 1        
    output = []    
    mask = (2 ** word_size_bits) - 1
    for subsection in range(output_words):
        output.append((integer >> (word_size_bits * subsection)) & mask)
    return output

def words_to_integer(words, word_size_bits):    
   # in_bytes = words_to_bytes(words, word_size_bits / 8)    
   # return bytes_to_integer(in_bytes)
    output = 0  
    for counter, word in enumerate(words):
        output |= word << (counter * word_size_bits)
    return output
        
def test_integer_to_words_words_to_integer():
    m = 133791287398124981241724871241217918273046208756138756139513210512305812353571834314311134
    words = integer_to_words(m, 384, 64)
    _m = words_to_integer(words, 64)
    assert m == _m, (m, _m, words)
        
def big_prime(size_in_bytes):           
    while True:
        candidate = random_integer(size_in_bytes)
        if candidate > 1 and is_prime(candidate):
            return candidate
            
def serialize_int(number):
    return integer_to_bytes(number, int((log(number) + 1) / 8))
    
def deserialize_int(serialized_int):
    return bytes_to_integer(serialized_int)       
 
def is_prime(n, _mrpt_num_trials=10): # from https://rosettacode.org/wiki/Miller%E2%80%93Rabin_primality_test#Python
    assert n >= 2
    # special case 2
    if n == 2:
        return True
    # ensure n is odd
    if n % 2 == 0:
        return False
    # write n-1 as 2**s * d
    # repeatedly try to divide n-1 by 2
    s = 0
    d = n-1
    while True:
        quotient, remainder = divmod(d, 2)
        if remainder == 1:
            break
        s += 1
        d = quotient
    assert(2**s * d == n-1)
 
    # test the base a to see whether it is a witness for the compositeness of n
    def try_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2**i * d, n) == n-1:
                return False
        return True # n is definitely composite
    
    random.seed(random_bytes(32))
    for i in range(_mrpt_num_trials):
        a = random.randrange(2, n)
        if try_composite(a):
            return False
 
    return True # no base tested showed n as composite
    
def random_bits(bit_count):
    blocks, extra = divmod(bit_count, 8)
    if extra:
        blocks += 1
    bit_string = ''.join(format(item, 'b').zfill(8) for item in bytearray(random_bytes(blocks)))    
    return [int(item) for item in bit_string[:bit_count]]
    
def quicksum(p):
    """ usage: quicksum(p) => int
    
        Sums range(p) significantly faster then sum(range(p)). """    
    e = p & 1
    q = p >> 1
    if not p & 1:
        e = q
        q -= 1           
    else:
        e = 0   
        q -= 0
    return (p * q) + e
    
def size_in_bits(integer):
    return int(log(integer or 1, 2)) + 1
    
def factor_integer(integer):
    factorization = dict()    
    for prime in prime_generator():
        _integer, remainder = divmod(integer, prime)
        if not remainder:  
            integer = _integer
            exponent = 1
            while not integer % prime:
                exponent += 1
                integer /= prime
            factorization[prime] = exponent
        if integer == 1:
            break
    return factorization
        
def modular_inverse2(a, n):
    inverse = pow(a, n - 2, n)
    if inverse == 0:
        raise ValueError("modular inverse does not exist")
    else:
        return inverse
        
        
_CACHE = {}

def prepare_random_integers(size, quantity, _cache=_CACHE):
    try:
        cached_integers = _cache[size]
    except KeyError:
        cached_integers = _cache[size] = []        
    cached_integers.extend(random_integer(size) for count in range(quantity))
    
def random_integer_fast(size, _cache=_CACHE, default_quantity=10000):
    try:
        entry = _cache[size]
    except KeyError:
        prepare_random_integers(size, default_quantity)
        entry = _cache[size]
        integer = entry.pop()
    else:
        try:
            integer = entry.pop()
        except IndexError:
            prepare_random_integers(size, default_quantity)
            integer = entry.pop()
    return integer
            
def secret_split(m, size, count, modulus):    
    splits = [random_integer(size) for counter in range(count - 1)]
    splits.append((m - sum(splits)) % modulus)    
    return splits
     
def dot_product(e, m):
    return sum((e[i] * m[i] for i in range(len(e))))            
            
def next_bit_permutation(v, mask):
    t = (v | (v - 1)) + 1
    return (t | ((((t & -t) / (v & -v)) >> 1) - 1)) & mask
    
def bit_generator(seed_weight, mask):    
    _seed_weight = seed_weight    
    while True:                
        yield seed_weight    
        if not seed_weight:            
            break        
        seed_weight = next_bit_permutation(seed_weight, mask) 
        
def find_low_weight_prime(size):
    mask = int('1' * size * 8, 2)   
    base = 2 ** (size * 8)
    for seed_weight in range(size * 8):
        for offset in bit_generator(seed_weight, mask):
            if is_prime(base + offset):
                return base, offset
                
def find_low_weight_safe_prime(size):
    mask = int('1' * size * 8, 2)   
    base = 2 ** (size * 8)
    for seed_weight in range(size * 8):
        for offset in bit_generator(seed_weight, mask):
            if is_prime(base + offset):
                if is_prime(((base + offset) - 1) / 2):
                    return base, offset
                
def isqrt(n): 
    # from https://stackoverflow.com/questions/15390807/integer-square-root-in-python
    assert n >= 0
    if n == 0:
        return 0
    i = n.bit_length() >> 1    # i = floor( (1 + floor(log_2(n))) / 2 )
    m = 1 << i    # m = 2^i
    #
    # Fact: (2^(i + 1))^2 > n, so m has at least as many bits
    # as the floor of the square root of n.
    #
    # Proof: (2^(i+1))^2 = 2^(2i + 2) >= 2^(floor(log_2(n)) + 2)
    # >= 2^(ceil(log_2(n) + 1) >= 2^(log_2(n) + 1) > 2^(log_2(n)) = n. QED.
    #
    while (m << i) > n: # (m<<i) = m*(2^i) = m*m
        m >>= 1
        i -= 1
    d = n - (m << i) # d = n-m^2
    for k in xrange(i-1, -1, -1):
        j = 1 << k
        new_diff = d - (((m<<1) | j) << k) # n-(m+2^k)^2 = n-m^2-2*m*2^k-2^(2k)
        if new_diff >= 0:
            d = new_diff
            m |= j
    return m                
        
def is_square(n):
    return (isqrt(n) ** 2) == n
    