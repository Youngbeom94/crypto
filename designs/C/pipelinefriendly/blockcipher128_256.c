#include "C:\Users\_\Documents\GitHub\crypto\analysis\iaca-win64\iacaMarks.h"

#define WORDSIZE32 unsigned long
#define ROUNDS 10

#define rotate_left(a, amount)(((a << amount) | (a >> (32 - amount))))

#define mixColumn(a, b, c, d, amount)({\
    a += b;\
    a = rotate_left(a, amount);\
    a ^= c;\
    a += d;})
    
#define shiftRows(b, c, d)({\
    b = rotate_left(b, 8);\
    c = rotate_left(c, 16);\
    d = rotate_left(d, 24);})
    
#define _permutation(a, b, c, d)({\
    mixColumn(a, b, c, d, 1);\
    mixColumn(b, c, d, a, 2);\
    mixColumn(c, d, a, b, 3);\
    mixColumn(d, a, b, c, 4);\
    shiftRows(b, c, d);})
    
#define add_key(a, b, c, d, keys, key_number)({\
    a ^= keys[(4 * key_number) + 0];\
    b ^= keys[(4 * key_number) + 1];\
    c ^= keys[(4 * key_number) + 2];\
    d ^= keys[(4 * key_number) + 3];}) 
    
#define store_data(data, a, b, c, d)({\
    data[0] = a; data[1] = b; data[2] = c; data[3] = d;})   
        
#define load_data(data, a, b, c, d)({\
    a = data[0]; b = data[1]; c = data[2]; d=data[3];})

#define iterate(permutation, a, b, c, d, iterations)\
({  unsigned int iteration;\
    for (iteration = 0; iteration < iterations; iteration++){\
        IACA_START\
        permutation(a, b, c, d);}\
    IACA_END})

void blockcipher128_256_encrypt(WORDSIZE32* data, WORDSIZE32* key){
    WORDSIZE32 a, b, c, d;
    load_data(data, a, b, c, d);
    
    add_key(a, b, c, d, key, 0);
    iterate(_permutation, a, b, c, d, ROUNDS);
    add_key(a, b, c, d, key, 1);  
    iterate(_permutation, a, b, c, d, ROUNDS);
    add_key(a, b, c, d, key, 2);
    
    store_data(data, a, b, c, d);}

#include "../performancetesting.c"    
int main(){    
    test_encrypt_performance_4x32_384(blockcipher128_256_encrypt, (1024 * 1024 * 1024) / 16);
    return 0;}
        