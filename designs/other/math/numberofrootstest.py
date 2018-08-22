from math import log

def test_number_of_roots():
    p = 4096 * 2 * 2 * 2
    outputs = dict()
    for x in range(2, p):
        initial = x
        outputs[x] = xoutput = [x, -x % p]
        for power in range(int(log(p, 2))):
            x = pow(x, 2, p)
            xoutput.extend((x, -x % p))        
    
   # for initial in range(2, p):
   #     xoutput = outputs[initial]
   #     print initial, "{}/{}".format(len(set(xoutput)), len(xoutput)), len(set(xoutput)) == len(xoutput)#xoutput
    average_number_of_roots = sum(len(set(output)) for output in outputs.values()) / (p - 2)
    print average_number_of_roots, abs(average_number_of_roots - log(p, 2))
    
if __name__ == "__main__":
    test_number_of_roots()
    