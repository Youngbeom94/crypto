# 0 4  8 12 16     <--- ----> column number is determined by (x / g) 
# 3 7 11 15     /\
# 2 6 10 14     || row number is determined by x % g
# 1 5  9 13     \/
   
def generate_modulus(generator):
    return (generator ** 2) + 1
    
def locate(element, generator, modulus):
    row_number = element % generator
    column_number = element / generator     
    assert ((generator * column_number) + row_number) % modulus == element, (element, row_number, column_number, ((generator * column_number) + row_number) % modulus)
    return row_number, column_number
    
def test_locate():
    for g in range(2, 64):    
        modulus = generate_modulus(g)
        for element in range(modulus):
            row, column = locate(element, g, modulus)
            
if __name__ == "__main__":
    test_locate()
    