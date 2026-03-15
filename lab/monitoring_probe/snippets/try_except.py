a = 1
try:
    b = 1 / 0
except ZeroDivisionError:
    b = 0
c = a + b
