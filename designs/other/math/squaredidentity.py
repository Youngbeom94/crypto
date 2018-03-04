# x   x + 1   x + 2
# x + 1 * x + 1 \equiv 1 \mod x * (x + 2)
# xx + 2x + 1 \equiv 1 \mod xx + 2x

def test_squared_identity():
    for x in range(1, 256):
        x_1 = x + 1
        x_2 = x + 2
        assert pow(x_1, 2, x * x_2) == 1
        
if __name__ == "__main__":
    test_squared_identity()
    