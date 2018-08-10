#x(2x - 2) = 2xx - 2x
#
#x(2x - 2)(3x - 6) = (2xx - 2x)(3x - 6) = 6xxx -12xx - 6xx + 12x = 6xxx - 18xx + 12x
#
#x(2x - 2)(3x - 6)(4x - 12) = (6xxx - 18xx + 12x)(4x - 12) = 

def parse_terms(expression_string, operators=('+', '-')):
    terms = []
    start_index = 0
    negative_term = ''
    for index, character in enumerate(expression_string):
        if character in operators:            
            terms.append(negative_term + expression_string[start_index:index].strip())
            if character == '-':
                negative_term = '-'    
            else:
                negative_term = ''
            start_index = index + 1            
    if index != start_index:
        terms.append(negative_term + expression_string[start_index:index + 1].strip())
    return terms
    
class Expression(object):
    
    def __init__(self, expression_string):
        self.terms = parse_terms(expression_string)
        
    def __mul__(self, other_expression):
        output = []
        for term in self.terms:
            for other_term in other_expression.terms:
                output.append(''.join((term, other_term)))
        
        
    @classmethod
    def unit_test(cls):
        expression0 = cls("2xx - 2x")
        expression1 = cls("6xxx - 18xx + 12x")
        
        expression2 = expression0 * expression1
        
def parse_terms_unit_test():
    expression0 = "2xx - 2x"
    expression1 = "6xxx - 18xx + 12x"
    
    terms0 = parse_terms(expression0)
    terms1 = parse_terms(expression1)
    print terms0
    print terms1
                     
if __name__ == "__main__":
    parse_terms_unit_test()
    