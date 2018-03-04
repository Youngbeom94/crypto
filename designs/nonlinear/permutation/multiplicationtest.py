def permutation(a, b, c, d, size=32, half_size=16, mask=(2 ** 32) - 1, multiplier=int("10101110000011110101010101", 2)):
    a ^= b  # ab
    c ^= d  # cd
    
    b ^= c  # bcd
    d ^= a  # dab
    d ^= b  # ac
    # ab, bcd, cd, ac
    
    a = (a * multiplier) & mask
    return a, b, c, d
    
def test_permutation():
    from crypto.analysis.visualization import test_4x32_function
    inputs = (1, 0, 0, 0)
    test_4x32_function(permutation, inputs)
    
if __name__ == "__main__":
    test_permutation()
    