HORIZONTAL_S_BOX = [11, 5, 4, 15, 12, 6, 9, 0, 13, 3, 14, 8, 1, 10, 2, 7]
HORIZONTAL_S_BOX256 = []
for byte in range(256):
    HORIZONTAL_S_BOX256.append((HORIZONTAL_S_BOX[byte >> 4] << 4) | HORIZONTAL_S_BOX[byte & 15])              

HORIZONTAL_INVERSE_S_BOX256 = [0] * 256
for index in range(256):
    HORIZONTAL_INVERSE_S_BOX256[HORIZONTAL_S_BOX256[index]] = index
    
def vertical_sbox(a, b, c, d): # 9 instructions 
    """ Optimal 4x4 s-box implementation; Applies 64 s-boxes in parallel on the columns. """                        
    t = a    
    a = (a & b) ^ c
    c = (b | c) ^ d
    d = (d & a) ^ t
    b ^= c & t        
    return a, b, c, d  
    
def permute_columns(a, b, c, d):
    return vertical_sbox(a, b, c, d)
    
def permute_rows(a, b, c, d):
    a = permute_row(a); b = permute_row(b); c = permute_row(c); d = permute_row(d)
    return a, b, c, d
    
def permute_row(word, mask=255, s_box=HORIZONTAL_S_BOX256):
    output = 0
    output |= s_box[word & mask]
    output |= s_box[(word >> 8) & mask] << 8
    output |= s_box[(word >> 16) & mask] << 16
    output |= s_box[(word >> 24) & mask] << 24
    return output
        
def mix_bytes(a, b, c, d, shift=16, mask=(2 ** 32) - 1):        
    a = (a ^ (b >> shift)) & mask
    c = (c ^ (d >> shift)) & mask
    a = (a ^ (b << shift)) & mask
    c = (c ^ (d << shift)) & mask                
    return a, b, c, d
    
def permutation(a, b, c, d):
    # s_box  /\  4 1 2 3
    #        |   3 4 1 2 
    #       \/   2 3 4 1 
    #            ------- 
    #s_box  <--> 1 2 3 4     
    a, b, c, d = permute_columns(a, b, c, d)    
    a, b, c, d = permute_rows(a, b, c, d)
    a, b, c, d = mix_bytes(a, b, c, d)
    a, b, c, d = mix_bytes(b, d, a, c)
    return a, b, c, d
    
def visualize_permutation():
    from crypto.analysis.visualization import test_4x32_function
    state = (1, 0, 0, 0)
    test_4x32_function(permutation, state)
    
if __name__ == "__main__":
    visualize_permutation()