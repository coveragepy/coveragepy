result = []
try:
    try:
        x = 1 / 0
    except ZeroDivisionError:
        result.append("inner")
        raise ValueError("wrapped")
except ValueError:
    result.append("outer")
done = True
