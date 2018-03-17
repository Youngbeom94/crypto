import multiprocessing
import multiprocessing.queues
from math import sqrt, log, fabs, ceil
import itertools

from crypto.utilities import gcd, is_prime, random_integer

def big_prime_in_bits(bits):
    while True:
        size = max(bits / 8, 1)
        shift = bits - (size * 8)    
        integer = random_integer(size)
        if shift < 0:
            integer >>= int(fabs(shift))
        elif shift > 0:
            integer <<= shift
            integer |= 1
        if integer in (0, 1):
            continue        
        
        if is_prime(integer):
            #assert log(integer, 2) <= bits
            #assert ceil(log(integer, 2)) == bits, (log(integer, 2), bits)
            return integer
    
def is_square(number):
    square_root = sqrt(number)
    if int(square_root) == square_root:
        return True
    else:
        return False
        
def square_root(number):
    return int(sqrt(number))
    
def calculate_ymax(n):    
    size = log(n, 2)
    return (2 ** (size / 2)) 
    
def factor_modulus(n, output=None):    
    if n % 2 == 0:
        factor1 = 1
        while n % 2 == 0:
            n /= 2
            factor1 *= 2
        factor2 = n / factor1
        return factor1, factor2
    if is_square(n):
        factor1 = int(sqrt(n))
        factor2 = factor1
        return factor1, factor2
    
    ymax = calculate_ymax(n)    
    for y in itertools.count(1):
        y_2 = y ** 2        
        if is_square(n + y_2):
            x = square_root(n + y_2)
            factor1 = gcd(x + y, n)
            factor2 = gcd(x - y, n)
            if factor1 == 1 or factor2 == 1 or (factor1 * factor2) != n:
                continue
            else:
                if output is None:
                    return factor1, factor2
                else:                    
                    output.put((factor1, factor2))
                    return
        if y == min(n, ymax): 
            print("Failed to factor n in {}/max({}, {}) steps".format(y, n, ymax))
            return None, None
        
def factor_modulus_multiprocess(n):
    cpu_count = multiprocessing.cpu_count()
    processes = []
    ymax = calculate_ymax(n)
    output = multiprocessing.queues.SimpleQueue()
    for process_number in range(cpu_count):
        scalar = process_number + 1
        process = multiprocessing.Process(target=factor_modulus, args=(n * scalar, output))
        processes.append(process)
        process.start()    
    factors = output.get()
    for process in processes:
        process.terminate()    
    return factors
            
def test_factor_modulus():
    from crypto.utilities import big_prime
    size = 2
    p = big_prime(size)
    q = big_prime(size)
    while p in (0, 1) or q in (0, 1):
        p = big_prime(size)
        q = big_prime(size)
    n = p * q    
    _p, _q = factor_modulus(n)
    assert set((_p, _q)) == set((p, q)), (_p, _q, p, q)
    print("nyfactoring unit test passed")
    
def test_factor_modulus_multiprocess():
    from crypto.utilities import big_prime
    size = 4
    p = big_prime(size)
    q = big_prime(size)
    while p in (0, 1) or q in (0, 1):
        p = big_prime(size)
        q = big_prime(size)
    n = p * q    
    _p, _q = factor_modulus_multiprocess(n)
    assert set((_p, _q)) == set((p, q)), (_p, _q, p, q)
    print("nyfactoring multiprocess unit test passed")
    
def test_factor_modulus_time():
    from timeit import default_timer
    #from crypto.utilities import big_prime
    outputs = dict((size, []) for size in range(3, 21))
    tests = 16
    with open("nyfactoring_time.txt", 'w') as _file:        
        for size, container in outputs.items():
            print("Testing modulus size: {}".format(size * 2))
            for test_number in range(tests):                   
                print("Test number: {}/{}".format(test_number, tests))
                p = big_prime_in_bits(size)
                q = big_prime_in_bits(size)    
                while p in (0, 1) or q in (0, 1):
                    p = big_prime(size)
                    q = big_prime(size)
                n = p * q                        
                
                start = default_timer()
                _p, _q = factor_modulus(n)
                end = default_timer()
                
                container.append("{} {}".format(size * 2, end - start))
            
            #_file.write("Factor and modulus size: {} + {} = {} (in bits)\n".format(size, size, size * 2))
            _file.write('\n'.join(container))
            _file.write('\n')
            _file.flush()
            
if __name__ == "__main__":
    #test_factor_modulus()
    #test_factor_modulus_multiprocess()
    test_factor_modulus_time()
    