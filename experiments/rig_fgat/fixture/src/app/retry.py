import time

def retry(fn, attempts=3, delay=0.1):
    for i in range(attempts):
        try:
            return fn()
        except Exception:
            if i == attempts - 1:
                raise
            time.sleep(delay * 2 ** i)
