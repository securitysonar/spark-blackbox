import time
from collections import deque

class Limiter:
    def __init__(self, per_second):
        self.per_second = per_second
        self.calls = deque()

    def allow(self):
        now = time.monotonic()
        while self.calls and now - self.calls[0] > 1:
            self.calls.popleft()
        if len(self.calls) < self.per_second:
            self.calls.append(now)
            return True
        return False
