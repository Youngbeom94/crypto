from crypto.utilities import prime_generator, modular_inverse
    
def test_sum_of_squares_identity():
    generator = prime_generator()
    next(generator)
    for q in generator:
        one_is_sum_of_squares = False
        for a in range(1, q):
            for b in range(q):
                #print("Testing {} + {}".format(pow(a, 2), pow(b, 2)))
                if (a + b) != 1 and (pow(a, 2) + pow(b, 2)) % q == 1:
                  #  print("Found sum of squares {}^2 + {}^2 mod {} = 1".format(a, b, q))
                    one_is_sum_of_squares = True
                    break
            if one_is_sum_of_squares:
                break            
        else:
            print("1 is not a sum of squares mod {}".format(q))
            break
            
def test_inverse_is_sum_of_squares():
    generator = prime_generator()
    next(generator)
    for q in generator:
        for a in range(1, q):            
            for b in range(q):
                inverse_is_sum_of_squares = False
                a2b2 = (pow(a, 2) + pow(b, 2)) % q
                if a2b2 == 0:
                    continue                
                inverse = modular_inverse(a2b2, q)
                for ai in range(1, q):
                    for bi in range(q):
                        if (pow(ai, 2) + pow(bi, 2)) % q == inverse:
                    #        print("Inverse of {} mod {} is a sum of squares".format(a2b2, q))
                            inverse_is_sum_of_squares = True
                            break
                    if inverse_is_sum_of_squares:
                        break
                else:
                    print("Inverse of {} is not a sum of squares mod {}".format(a2b2, q))
                    raise SystemExit()
                    
def test_sum_of_squares_group():
    generator = prime_generator()
    next(generator)
    for q in generator:
        for a in range(1, q):
            for b in range(q):
                a2b2 = (pow(a, 2) + pow(b, 2)) % q
                if a2b2 != 0:
                    #print("Computing inverse of {} mod {}".format(a2b2, q))
                    inverse = modular_inverse(a2b2, q)
        else:
            print("Sums of squares mod {} form a multiplicative group".format(q))
                        
                        
# aa + bb
# b = (a + c)
# aa + (a + c)(a + c)
# aa + aa + ac + ac + cc
# 2aa + 2ac + cc
# 2a(a + c) + cc
                    
    
# g(aa + bb)
# g(cc + dd)

# ag(cc + dd) = agcc + agdd
# bg(cc + dd) = bgcc + bgdd

# cg(aa + bb) = aagc + bbcg
# dg(ag + bb) = aadg + bbdg

# (aa + bb)
# (cc + dd)
# a(cc + dd) = acc + add
# c(aa + dd) = aac + cdd

# aa(cc + dd) = aacc + aadd
# cc(aa + bb) = aacc + bbcc




if __name__ == "__main__":
    #test_sum_of_squares_identity()
    #test_inverse_is_sum_of_squares()
    test_sum_of_squares_group()
    