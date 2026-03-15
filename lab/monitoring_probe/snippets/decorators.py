def trace(func):
    def wrapper(*args):
        return func(*args)
    return wrapper

def bold(func):
    def wrapper(*args):
        return f"**{func(*args)}**"
    return wrapper

@bold
@trace
def greet(name):
    return f"hello {name}"

result = greet("world")
