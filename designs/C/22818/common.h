#define WORDSIZE unsigned long
#define load_state(state, a, b, c, d)({a = state[0]; b = state[1]; c = state[2]; d=state[3];})
#define store_state(state, a, b, c, d)({state[0] = a; state[1] = b; state[2] = c; state[3] = d;})
    