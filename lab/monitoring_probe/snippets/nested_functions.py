def outer(x):
    def inner(y):
        return x + y
    return inner(10)

result = outer(5)
