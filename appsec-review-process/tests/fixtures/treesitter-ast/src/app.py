import os
from pkg import util


def load(path):
    return util.read(os.path.join("/", path))


class Store:
    def get(self, key):
        return load(key)
