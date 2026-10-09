from distutils.version import LooseVersion

def newer(a, b):
    return LooseVersion(a) > LooseVersion(b)
