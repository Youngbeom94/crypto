def rotate_left(word, amount, mask=0xFFFFFFFF): return ((word << amount) | (word >> (32 - amount))) & mask;
    
def f(x): return x ^ branch(x);
    
def branch(x): x ^= rotate_left(x, 3); x ^= rotate_left(x, 15); x ^= rotate_left(x, 17); x ^= rotate_left(x, 30); return x
    
def choice(a, b, c): return c ^ (a & (b ^ c));
    
def permutation(a, b, c, d, mask=(2 ** 32) - 1):    
    fb = f(b)
    fc = f(c)
    fd = f(d)
    a ^= choice(fb, fc, fd)
    
    fa = f(a)
    b ^= choice(fc, fd, fa)
    
    fb = f(b)
    c ^= choice(fd, fa, fb)
    
    fc = f(b)
    d ^= choice(fa, fb, fc)
    return a, b, c, d
    
def visualize_permutation():
    from crypto.analysis.visualization import test_4x32_function
    state = (1, 0, 0, 0)
    test_4x32_function(permutation, state)
            
if __name__ == "__main__":
    visualize_permutation()
    