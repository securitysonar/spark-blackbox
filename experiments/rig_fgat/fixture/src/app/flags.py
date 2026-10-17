import os

def enabled(name):
    return os.environ.get(f'FLAG_{name.upper()}', '0') == '1'
