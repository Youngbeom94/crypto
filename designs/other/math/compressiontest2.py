from math import log, ceil

from crypto.utilities import modular_inverse
 
Q = 257
RATIO = 6

def hamming_weight(a):
    return format(a, 'b').count('1')
    
def hamming_distance(a, b):
    return int(abs(a - b))
    #return hamming_weight(a ^ b)
    
def lossy_compress_block(data, q=Q, ratio=RATIO, cache={}):
    try:
        return cache[data]
    except KeyError:
        pass
        
    if not data:
        return data, 0
        
    min_distance = 8
    best_code = data
    for short_inverse in range(2, 2 ** ratio):        
        code = modular_inverse(short_inverse, q)
        distance = hamming_distance(data, code)
        if distance < min_distance:
            min_distance = distance
            best_code = short_inverse
    cache[data] = (best_code, min_distance)    
    return best_code, min_distance
    
def decompress_block(compressed_data, q=Q, cache={}):
    if not compressed_data:
        return compressed_data
    try:
        return cache[compressed_data]
    except KeyError:
        decompressed_data = modular_inverse(compressed_data, q)
        cache[compressed_data] = decompressed_data
        return decompressed_data    
        
def compress_data(data, q=Q, ratio=RATIO):
    output = 0    
    for counter, byte in enumerate(data):
        code = lossy_compress_block(byte, q, ratio)[0]           
        output |= (code << (counter * ratio)) 
    data_size = int(ceil(counter * (float(ratio) / 8)))
    return output, data_size
    
def decompress_data(compressed_data, q=Q, ratio=RATIO):
    output = bytearray()
    data = compressed_data
    mask = (2 ** ratio) - 1
    while data:    
        code = data & mask                
        data >>= ratio
        byte = decompress_block(code, q)        
        output.append(byte)
    return output 
                
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
    compressed_data, compressed_size = compress_data(data)
    decompressed_data = decompress_data(compressed_data)
    print list(data)    
    print compressed_data
    print decompressed_data
    print len(data), len(decompressed_data), len(format(compressed_data, 'b')) / 8
    print ''.join(chr(ordinal) for ordinal in decompressed_data)    
    print [hamming_distance(data[index], decompressed_data[index]) for index in range(len(data))]
    
if __name__ == "__main__":
   # test_lossy_compress_block()    
    test_compress_data_decompress_data()
    