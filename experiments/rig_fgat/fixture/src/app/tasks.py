import asyncio

@asyncio.coroutine
def ping():
    yield from asyncio.sleep(0)
    return 'pong'
