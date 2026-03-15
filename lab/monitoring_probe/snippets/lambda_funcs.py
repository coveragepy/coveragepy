double = lambda x: x * 2
add = lambda x, y: x + y
nums = [1, 2, 3, 4, 5]
doubled = list(map(double, nums))
total = add(sum(doubled), 10)
