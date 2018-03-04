# inverse(x, p * q) == inverse(x, p) + p * r
# find x such that inverse(x, p) is short
# factor (p * q) + 1
#   - with high probability, consists of a few small factors and a larger factor
#   - product of small factors is a short inverse

# 11 * 17 == 187
# 2 * 2 * 47 = 188
# 4 * 47 mod 187 == 1
#inverse(4, 187) == inverse(4, 11) + 11 * r1

# 11 * 17 * 2 == 374
#        + 1  == 375
# 3 * 125     == 375
# inverse(3, 187) == inverse(3, 11) + 11 * r2
from crypto.utilities import factor_integer, modular_inverse

def unpack_factors(factor_dict):
    output = []
    for factor, power in factor_dict.items():
        output.append(factor ** power)
    return output
    
def test_factoring_algorithm():
    p = 11
    q = 17
    n = p * q
    for x in range(1, 11):
        n_x = (n * x) + 1
        factors = unpack_factors(factor_integer(n_x))
        #print factors
        smallest_factor = min(factors)
        print factors, modular_inverse(smallest_factor, p)
        if smallest_factor < n:
            x_pr = modular_inverse(smallest_factor, n)
         #   print x_pr
        
        
       # big_factor = max(factors)        
       # print factors
       # factors.remove(big_factor)        
       # if factors:
       #     small_factor = 1
       #     for factor in factors:
       #         small_factor *= factor
       # else:
       #     small_factor = big_factor
       # print min(small_factor, big_factor)
        
if __name__ == "__main__":
    test_factoring_algorithm()
    