result = []
try:
    x = 1
except ValueError:
    result.append("except")
else:
    result.append("else")
finally:
    result.append("finally")
done = True
