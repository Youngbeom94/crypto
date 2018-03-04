# computing modular inverses
# factor nx + 1
# a subset product of factors * remaining subset product of factors is congruent to 1 modulo n
# ensure each subset product is smaller than n
from crypto.utilities import factor_integer

def generate_modular_inverses(n):
    inverses = []
    for x in range(1, n):
        nx_1 = (n * x) + 1
        factors = factor_integer(nx_1)
        
        for y, y_i in subset_product(factors):
            if y > n or y_i > n or (y, y_i) in inverses:
                continue
            else:
                assert (y * y_i) % n == 1
                inverses.append((y, y_i))
    return inverses
                
def subset_product(factors):
    for prime, exponent in factors.items():
        