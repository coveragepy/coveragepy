import io

with io.StringIO() as f1, io.StringIO() as f2:
    f1.write("hello")
    f2.write("world")
    result = f1.getvalue() + f2.getvalue()
done = True
