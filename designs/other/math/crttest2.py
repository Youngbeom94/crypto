# from https://rosettacode.org/wiki/Chinese_remainder_theorem#Python

# Python 2.7
def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
 
    for n_i, a_i in zip(n, a):
        p = prod / n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod
 
 
def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a / b
        a, b = b, a%b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1
 
#def generate_private_key 

if __name__ == '__main__':
    #n = [3, 5, 7]
    #a = [2, 3, 2]
    
    from crypto.utilities import random_integer, big_prime
    
    #crt cryptosystem
    #public key: x mod k1 
    #shared secret: x mod k1 * k2 (computed via crt)        
    # k1i = modular_inverse(k1, p)
    
    # m1 = x mod p
    # m2 = x mod k1
    # h = modular_inverse(k1, p) * (m1 - m2)
    # m = m2 + hk1
    # pub1 = m, pk1 + e
    
    # k2i = modular_inverse(k1, pk1 + e)
    # m1 = pub1
    # m2 = x mod k2
    # h = modular_inverse(k2, pk1 + e) * (m1 - m2)
    # m = m2 + hk2
    # share = m

    
    while True:
        a = random_integer(64)
        
        k1 = big_prime(32)
        k2 = big_prime(32)
        
        puba = k1 + (random_integer(16) << 110)
        pubb = k2 + (random_integer(16) << 110)

        try:
            sharea = chinese_remainder([pubb, k1], [a, a])
            shareb = chinese_remainder([puba, k2], [a, a])
            breaktest = chinese_remainder([puba, pubb], [a, a])
        except ZeroDivisionError:
            continue
        else:
            print sharea
            print shareb
            print breaktest
            break