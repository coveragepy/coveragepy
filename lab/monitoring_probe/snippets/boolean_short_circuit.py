def truthy():
    return True

def falsy():
    return False

a = truthy() and truthy()
b = falsy() and truthy()
c = truthy() or falsy()
d = falsy() or truthy()
e = falsy() or falsy() or truthy()
result = (a, b, c, d, e)
