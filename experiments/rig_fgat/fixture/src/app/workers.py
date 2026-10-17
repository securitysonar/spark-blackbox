import threading

def start(fn):
    t = threading.Thread(target=fn)
    t.setDaemon(True)
    t.start()
    return threading.currentThread().name
