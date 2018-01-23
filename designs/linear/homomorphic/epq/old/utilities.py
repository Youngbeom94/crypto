from math import log
from os import urandom as random_bytes
from hmac import compare_digest as constant_time_comparison

def integer_to_bytes(integer, _bytes):
    return bytearray((integer >> (8 * (_bytes - 1 - byte))) & 255 for byte in range(_bytes))
    
def bytes_to_integer(data):
    output = 0    
    size = len(data)
    for index in range(size):
        output |= data[index] << (8 * (size - 1 - index))
    return output
    
def serialize_int(number):
    return str(number)

def deserialize_int(serialized_int):
    return int(serialized_int)
    
def xor_subroutine(bytearray1, bytearray2): 
    size = min(len(bytearray1), len(bytearray2))    
    for index in range(size):
        bytearray1[index] ^= bytearray2[index]
        
def get_permission(prompt):    
    while True:
        try:
            _input = raw_input(prompt).lower()[0]
        except IndexError:
            pass
        else:
            if _input == 'y':
                return True
            elif _input == 'n':
                return False

def slide(iterable, x=16):
    """ Yields x bytes at a time from iterable """
    slice_count, remainder = divmod(len(iterable), x)
    for position in range((slice_count + 1 if remainder else slice_count)):
        _position = position * x
        yield iterable[_position:_position + x]  
            
def random_integer(size_in_bytes):
    """ usage: random_integer(size_in_bytes) => random integer
    
        Returns a random integer of the size specified, in bytes. """
    return bytes_to_integer(bytearray(random_bytes(size_in_bytes)))
    
def size_in_bits(integer):
    return int(log(integer, 2)) + 1
    
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
        
def big_prime(size_in_bytes):           
    while True:
        candidate = random_integer(size_in_bytes)
        if candidate > 1 and is_prime(candidate):
            return candidate
            
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
    
        
        