#   0
#     3   6   9  12
#     2   5   8  11   
#     1   4   7  10   


def print_elements(elements):
    lines = parse_rows(elements)
    print lines[0]   
    del lines[0]
    for line in lines:
        print line
        
def parse_rows(elements):    
    lines = []
    line = [elements[0]]
    for element in elements[1:]:
        if element < line[-1]:            
            lines.append(line)
            line = []            
        line.append(element)
    lines.append(line)
    return lines
    
def test_print_elements():
    g = 5
    q = 13
    elements = [(g * x) % q for x in range(q)]
    print "Elements: ", elements
    print_elements(elements)
    
if __name__ == "__main__":
    test_print_elements()
    