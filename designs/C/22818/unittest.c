#include <time.h>
#include <stdio.h>

#include "common.h"
#include "permutation.h"
#include "unittest.h"

#define print_state(a, b, c, d)(printf("a = %lu\nb = %lu\nc = %lu\nd = %lu\n", a, b, c, d))

void permutation_unit_test(){    
    printf("Beginning permutation unit test\n");
    WORDSIZE a, b, c, d;
    unsigned long _index;    
    a = 1; b = 0; c = 0; d = 0;
    WORDSIZE state[4]; store_state(state, a, b, c, d);
    
    printf("Initial state:\n");
    print_state(a, b, c, d);
    
    printf("Permuting 3,000,000 16-byte blocks (~48MB...)\n");
    clock_t begin = clock();
    for (_index = 0; _index < 3000000; _index++){            
        permutation(state);}
    clock_t end = clock();    
    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;    
    printf("Time required: %.2fs\n", time_spent);    
    
    load_state(state, a, b, c, d);
    print_state(a, b, c, d);}
    
    /*printf("Inverting...\n");
    for (_index = 0; _index < 3000000; _index++){
        crypto_prp_inverse_permutation(state);}
    printf("Final state:\n");
    load_state(state, a, b, c, d);
    print_state(a, b, c, d);*/
       