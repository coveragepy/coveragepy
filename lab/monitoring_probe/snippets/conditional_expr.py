x = 5
a = "pos" if x > 0 else "neg"
b = "big" if x > 100 else "small"
c = "zero" if x == 0 else ("one" if x == 1 else "other")
result = f"{a} {b} {c}"
