#a b c
#d e f
#
#key1 = 0 1 2
#
#aa + ab + ac     ba + bb + bc    ac + bc + cc
#ad + ae + af     bd + be + bf    cd + ce + cf
#
#
#key2 = 3 4 5
#
#da + db + dc     ea + eb + ec    fa + fb + fc
#dd + de + df     ed + ee + ef    fd + fe + ff
#
#
#da + db + dc + ea + eb + ec + fa + fb + fc
#ad + bd + cd + ae + be + ce + af + bf + cf
#
#
#ad + ae + af + bd + be + bf + cd + ce + cf

from splitfhe import *

def test():
    g = secret_split(0, 32, 256, MODULUS)
    key1 = generate_key()
    key2 = generate_key()
    
    g1 = mul(g, g, key1)
    g2 = mul(g, g, key2)
        
    assert g1 != g2
    
    share1 = decrypt(g2, key1)
    share2 = decrypt(g1, key2)
    
    assert share1 == share2
    
    print sum(g) % MODULUS    
    print decrypt(g1, key1)
    print decrypt(g2, key2)
    
if __name__ == "__main__":
    test()
