# requires: 3.14+
def greet(name: str) -> str:
    return f"hello {name}"

x: int = 1
y: list[str] = []
result = greet("world")
