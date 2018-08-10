#2   3   4   5   6   7   8   9   10  11  12  13  14  15  16
#
#2 * 4 * 8 * 16 = 2^1 * 2^2 * 2^3 * 2^4 = 2^(1 + 2 + 3 + 4) = 2^((n * (n + 1)) / 2)
#
#
#    3       5   6   7       9   10  11  12  13  14  15
#    
# (2^k)-1      (2^k)-1               (2^k)-1
# 
# 2^(1.5)
# 2^(((2^2) - 1) + i(1.0/((2^(2 - 1)) - 1)))    i = 1, 2, 3, ... (2^k) - 1
# 2^(((2^k) - 1) + i(1.0/((2^(k - 1)) - 1)))    1x + 2x + 3x + 4x + 5x ... + ((2^k) - 1)x
#                                              x * ((n * (n + 1)) / 2) ; n = (2^k) - 1
#                                              x = 1.0/((2^(k - 1)) - 1)
#                                              ((2^k) - 1) * (1.0/((2^(k - 1)) - 1))
# 2^(((2^(k - 1)) - 1) + x(1.0/((2^(k - 1)) - 1)))
#            
#
#number of elements between 2^k and 2^(k - 1) = 2^(k - 1) - 1
#exponent fraction per element = 1.0/(number of elements + 1) OR log(2^k, 2)
#sum of exponent fractions = exponent fraction per element * ((number of elements * (number of elements + 1)) / 2)
#sum of exponents = (k - 1) * ((number of elements * (number of elements + 1)) / 2)
#exponent = sum of exponents + sum of exponent fractions
#value = 2^exponent
from math import log, ceil

def quick_sum(n):
    return (n * (n + 1)) / 2
    
def factorial_approximation(n):
    max_power_of_two = int(log(n, 2))
    print("Sum of powers: {}".format(quick_sum(max_power_of_two)))
    output = 2 ** quick_sum(max_power_of_two)
    print("Max power of two: {}".format(max_power_of_two))
    print("Base output: {}".format(output))
    for k_minus_1 in range(1, max_power_of_two):
        number_of_elements = pow(2, k_minus_1) - 1
        print("Number of elements between 2^{} and 2^{}: {}".format(k_minus_1, k_minus_1 + 1, number_of_elements))
        fraction_per_element = log(pow(2, k_minus_1), 2) / (number_of_elements + 1)
        print("Fraction of exponent per element: log({}) = {}".format(number_of_elements + 1, fraction_per_element))
        sum_of_elements = quick_sum(number_of_elements)
        fraction_sum = fraction_per_element * quick_sum(sum_of_elements)
        exponent_sum = (k_minus_1) * quick_sum(sum_of_elements)
        print("Generated exponent: {} + {} = {}".format(exponent_sum, fraction_sum, exponent_sum + fraction_sum))
        output *= pow(2, exponent_sum + fraction_sum)
    return output
    
def test_factorial_approximation():
    from math import factorial
    print factorial_approximation(2), factorial(2)
    print
    print factorial_approximation(3), factorial(3)
    print
    print factorial_approximation(4), factorial(4)
    print
    print factorial_approximation(5), factorial(5)
    print
    print factorial_approximation(8), factorial(8)
    
if __name__ == "__main__":
    test_factorial_approximation()
    