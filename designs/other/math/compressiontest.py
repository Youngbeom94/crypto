from math import log

from crypto.utilities import modular_inverse
 
Q = 257

def hamming_weight(a):
    return format(a, 'b').count('1')
    
def hamming_distance(a, b):
    return hamming_weight(a ^ b)
    
def lossy_compress_block(data, q=Q):
    if not data:
        return data, 0
        
    min_distance = 8
    best_code = modular_inverse(data, q)
    for short_inverse in range(2, 16):        
        code = modular_inverse(short_inverse, q)
        distance = hamming_distance(data, code)
        if distance < min_distance:
            min_distance = distance
            best_code = short_inverse
    return best_code, min_distance
    
def decompress_block(compressed_data, q=Q):
    if not compressed_data:
        return compressed_data
    return modular_inverse(compressed_data, q)    
        
def compress_data(data, q=Q):
    output = []
    first_nibble = True
    for byte in data:
        code = lossy_compress_block(byte, q)[0]        
        if first_nibble:
            block = code
            first_nibble = False
        else:
            block |= code << 4
            output.append(block)
            first_nibble = True
    return output
    
def decompress_data(compressed_data, q=Q):
    data = []
    for byte in compressed_data:
        code1 = byte & 15
        code2 = byte >> 4
        byte1 = decompress_block(code1, q)
        byte2 = decompress_block(code2, q)
        data.extend((byte1, byte2))
    return data 
        
        
def test_lossy_compress_block():
    max_distance = 0
    for data in range(257):
        code, distance = lossy_compress_block(data)
        _data = decompress_block(code)
        assert hamming_distance(data, _data) == distance
        try:
            print "{} -> {} (D: {}; Size: {}; Compressed size: {}".format(data, code, distance, log(data, 2), log(code, 2))          
        except ValueError:
            continue
        
        if distance > max_distance:
            max_distance = distance
    print max_distance
    
def test_compress_data_decompress_data():
    data = bytearray("I'm not really sure how to impart meaningful structure to this data")
    compressed_data = compress_data(data)
    decompressed_data = decompress_data(compressed_data)
    print list(data)
    print decompressed_data
    print len(compressed_data), len(data)
    #print ''.join(chr(ordinal) for ordinal in decompressed_data)    
    
if __name__ == "__main__":
   # test_lossy_compress_block()    
    test_compress_data_decompress_data()
    