nums = [1, 2, 3, 4, 5]
squares = [x * x for x in nums]
evens = [x for x in nums if x % 2 == 0]
total = sum(x for x in squares)
lookup = {x: x * x for x in nums}
