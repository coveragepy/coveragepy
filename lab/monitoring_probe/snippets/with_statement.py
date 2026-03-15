import io

with io.StringIO() as f:
    f.write("hello")
    result = f.getvalue()
done = True
