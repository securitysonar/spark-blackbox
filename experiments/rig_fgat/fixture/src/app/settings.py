import configparser

def read(path):
    cp = configparser.SafeConfigParser()
    cp.read(path)
    return cp
