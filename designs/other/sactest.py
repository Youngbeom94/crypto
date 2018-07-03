def rotate_left8(word, amount):
    assert 0 <= amount < 8, amount
    return ((word << amount) | (word >> (8 - amount))) & 255
    
def sac8_row(word, cache=dict()):     
    try:
        return cache[word]
    except KeyError:
        entry = word
        word ^= rotate_left8(word, 2)
        word ^= rotate_left8(word, 5)
        cache[entry] = word
        return word
    
def sac8_columns(words):   
    temp = words[:]
    for index in range(8):
        words[index] ^= temp[(index + 1) % 8]
    temp[:] = words
    for index in range(8):
        words[index] ^= temp[(index + 3) % 8]
    
def shift_rows(words):
    for index in range(1, 8):
        words[index] = rotate_left8(words[index], index)
        
def diffuse_block(words):
    #for index, word in enumerate(words):
    #    words[index] ^= rotate_left8(1, index)
    #sac8_columns(words)
    #for index, word in enumerate(words):
    #    words[index] = sac8_row(word)
       
    #for index, word in enumerate(words):
    #    words[index] = sac8_row(word)
    #sac8_columns(words)    
    #shift_rows(words)
    #sac8_columns(words)    

    #for index, word in enumerate(words):
    #    words[index] = sac8_row(word)
    
    
def print_words(words):
    print '\n'.join(format(word, 'b').zfill(8) for word in words)
    
def print_weight(words):
    print sum(format(word, 'b').count('1') for word in words)
    
def print_total_distance(words1, words2):
    print("{}/{}").format(sum(format(words1[index] ^ words2[index], 'b').count('1') for index in range(len(words1))),
                          sum(8 for count in range(len(words1))))
        
def print_distances(words1, words2):
    print [format(words1[index] ^ words2[index], 'b').count('1') for index in range(len(words1))]
    
def test_diffuse_block():
    print_weight([sac8_row(1)])
    print

    words0 = [1, 0, 0, 0, 0, 0, 0, 0]
    sac8_columns(words0)
    print_weight(words0)
    print
    #words = [1, 2, 4, 8, 16, 32, 64, 128]
    words = [3] + ([0] * 7)    
    diffuse_block(words)
    print
    print_words(words)
    print_weight(words)
    
    words2 = [2] + ([0] * 7)
    diffuse_block(words2)
    print
    print_words(words2)
    print_weight(words2)
    
    print_distances(words, words2)
    print_total_distance(words, words2)
    
if __name__ == "__main__":
    test_diffuse_block()
    
    
    