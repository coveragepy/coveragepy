# requires: 3.10+
def classify(x):
    match x:
        case 0:
            return "zero"
        case n if n > 0:
            return "positive"
        case _:
            return "negative"

results = [classify(0), classify(5), classify(-1)]
