import platform

def status():
    return {'ok': True, 'python': platform.python_version()}
