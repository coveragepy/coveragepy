class Animal:
    kind = "unknown"

    def __init__(self, name):
        self.name = name

    def speak(self):
        return f"{self.name} says hello"

class Dog(Animal):
    kind = "dog"

    def speak(self):
        return f"{self.name} barks"

d = Dog("Rex")
result = d.speak()
