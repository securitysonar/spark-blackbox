from collections import Mapping

class Cache(dict):
    def merge(self, other):
        if isinstance(other, Mapping):
            self.update(other)
        return self
