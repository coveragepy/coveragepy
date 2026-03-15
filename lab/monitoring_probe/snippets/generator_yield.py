def gen(n):
    for i in range(n):
        yield i * 2

result = list(gen(3))
