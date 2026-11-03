import os

LIMIT = 4  # ANCHOR:none


def load(path):  # BEGIN:load
    keep = lambda name: name.endswith(".txt")  # ANCHOR:load
    names = [name for name in os.listdir(path) if keep(name)]

    def inner(value):  # BEGIN:inner
        return value.strip()  # ANCHOR:inner END:inner

    return [inner(name) for name in names]  # ANCHOR:load END:load


class Store:
    async def fetch(self, key):  # BEGIN:fetch
        return await self.get(key)  # ANCHOR:fetch END:fetch
