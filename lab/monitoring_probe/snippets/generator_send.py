def accumulator():
    total = 0
    while True:
        value = yield total
        if value is None:
            break
        total += value

gen = accumulator()
next(gen)
gen.send(10)
gen.send(20)
try:
    gen.send(None)
except StopIteration:
    pass
