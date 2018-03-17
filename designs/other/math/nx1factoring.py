import itertools
from math import sqrt

from crypto.utilities import gcd

def factoring_algorithm(n):
    for x in itertools.count(1):
        if x == n:
            print("Failure")
            break
        nx_1 = (n * x) + 1
      #  print "Factoring n{} + 1".format(x)
        square_factor = sqrt(nx_1)
        if int(square_factor) == square_factor:
           # print "Found product of squares: {}".format(square_factor)
           # print gcd(square_factor - 1, n)
           # print gcd(square_factor + 1, n)
            p = gcd(square_factor - 1, n)
            q = gcd(square_factor + 1, n)
            if p * q != n:
                continue
            else:
                print "False positive: ", p, q, p * q
            return p, q#gcd(square_factor - 1, n), gcd(square_factor + 1, n)                    
            
def test_factoring_algorithm():
    from crypto.utilities import big_prime
    p = big_prime(4)
    q = big_prime(4)    
    while p in (1, 0) or q in (1, 0):
        p = big_prime(4)
        q = big_prime(4)
    n = p * q
    print p, q, n
    _p, _q = factoring_algorithm(n)
    assert set((_p, _q)) == set((p, q)), (_p, _q, p, q)
    
if __name__ == "__main__":
    test_factoring_algorithm()
    