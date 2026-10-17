import inspect

def arg_names(fn):
    return inspect.getargspec(fn).args
