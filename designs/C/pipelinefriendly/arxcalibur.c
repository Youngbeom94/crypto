#include "C:\Users\_\Documents\GitHub\crypto\analysis\iaca-win64\iacaMarks.h"
#define WORDSIZE32 unsigned long

#define rotate_left(word, amount)(((word << amount) | (word >> (32 - amount))))
#define mixColumns(a, b, c, d)({a += b; c += d; b ^= c; d ^= a;})
#define shiftRows(b, c, d, shift1, shift2, shift3)({b = rotate_left(b, shift1); c = rotate_left(c, shift2); d = rotate_left(d, shift3);})

#define permutation(a, b, c, d)({\
    a ^= 0xFFFFFFFF;\
    d ^= 0xFFFFFFFF;\
    mixColumns(a, b, c, d);\
    shiftRows(b, c, d, 1, 2, 3);\
    mixColumns(a, b, c, d);\
    shiftRows(b, c, d, 4, 8, 12);\
    mixColumns(a, b, c, d);\
    shiftRows(b, c, d, 8, 12, 16);})
                    
#define add_key(a, b, c, d, keys, key_number)({\
    a ^= keys[(4 * key_number) + 0];\
    b ^= keys[(4 * key_number) + 1];\
    c ^= keys[(4 * key_number) + 2];\
    d ^= keys[(4 * key_number) + 3];}) 

#define store_data(data, a, b, c, d)({\
    data[0] = a; data[1] = b; data[2] = c; data[3] = d;})   
        
#define load_data(data, a, b, c, d)({\
    a = data[0]; b = data[1]; c = data[2]; d=data[3];})

#define iterate(permutation, a, b, c, d, iterations)({\
    unsigned int iteration;\
    for (iteration = 0; iteration < iterations; iteration++){\
        IACA_START\
        permutation(a, b, c, d);}\
    IACA_END})
    
void blockcipher128_384_encrypt(WORDSIZE32* data, WORDSIZE32* key){    
    WORDSIZE32 a, b, c, d;
    load_data(data, a, b, c, d);
    
    add_key(a, b, c, d, key, 0);
    iterate(permutation, a, b, c, d, 10);
    add_key(a, b, c, d, key, 1);
    iterate(permutation, a, b, c, d, 10);    
    add_key(a, b, c, d, key, 2);
    
    store_data(data, a, b, c, d);}    
    
#include "../performancetesting.c"    
int main(){            
    test_encrypt_performance_4x32_384(blockcipher128_384_encrypt, (1024 * 1024 * 1024) / 16);
    return 0;}    

    