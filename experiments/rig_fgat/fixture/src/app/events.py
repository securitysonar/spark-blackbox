from collections import defaultdict

_handlers = defaultdict(list)

def on(name, fn):
    _handlers[name].append(fn)

def emit(name, *args):
    for fn in _handlers[name]:
        fn(*args)
