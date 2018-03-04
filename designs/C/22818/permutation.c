#include "common.h"

#define ROUNDS 32
#define rotate_left(word, amount)((word << amount) | (word >> (32 - amount)))
#define f(x)(x ^ L(x))
#define L(x)({x ^= rotate_left(x, 3); x ^= rotate_left(x, 15); x ^= rotate_left(x, 17); x ^= rotate_left(x, 30);})
#define choice(a, b, c)(c ^ (a & (b ^ c)))

void permutation(WORDSIZE* state){
    WORDSIZE a, b, c, d;
    unsigned int index;
    load_state(state, a, b, c, d);    
    for (index = 0; index < ROUNDS; index++){
        a ^= index;
        a ^= choice(f(b), f(c), f(d)); b ^= choice(f(c), f(d), f(a));
        c ^= choice(f(d), f(a), f(b)); d ^= choice(f(a), f(b), f(c));}
    store_state(state, a, b, c, d);}
                    