from math import log

from crypto.utilities import modular_inverse, modular_subtraction

Q = (2 ** (193 * 8)) + 1

def separate(c, q=Q):
    ai = 1 << 256
    a = modular_inverse(ai, q)
    s_lsb = ((c * ai) % q) % ai
    
    as_lsb = (a * s_lsb) % q
    e_lsb = modular_subtraction(c, as_lsb, q) % ai
        
    c_t = modular_subtraction(c, e_lsb, q)
    s_isb = (((ai * c_t) % q) % (ai << 256)) >> 256
    
    as_isb = (a * ((s_isb << 256) + s_lsb)) % q
    e_isb = ((modular_subtraction(c, as_isb, q) % (ai << 256)) >> 256) % ai
    return s_lsb, e_lsb, s_isb, e_isb
    
        
def test_separate():
    from crypto.utilities import random_integer
    x, y = random_integer(64) << 256, random_integer(128)
    assert x < Q
    assert y < Q
    assert x + y < Q
    ai = 1 << 256
    a = modular_inverse(ai, Q)
    c = ((a * x) + y) % Q
    
    e = c % ai
    assert e == y % ai, (e, y % ai)
    
    s = ((c * ai) % Q) % ai
    assert s == x % ai
    
    #c_t = (c * ai) % Q
    #c_t = modular_subtraction(c_t, s, Q)
    #c_t = (c_t * a) % Q
    #e = c_t % ai
    #assert e == y % ai, (e, y % ai)
        
    _x, _y, _z, _w = separate(c, Q)
    assert _x == s, (_x, s)
    assert _y == e, (_y, e)
    
    s_isb = (x % (ai << 256)) >> 256
    assert _z == s_isb, (_z, s_isb)
    
    e_isb = (y * (ai << 256)) >> 256
    assert _w == e_isb, (_w, e_isb)
    
    
    
if __name__ == "__main__":
    test_separate()
    