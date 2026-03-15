import asyncio

async def fetch(x):
    await asyncio.sleep(0)
    return x * 2

async def main():
    a = await fetch(1)
    b = await fetch(2)
    return a + b

result = asyncio.run(main())
