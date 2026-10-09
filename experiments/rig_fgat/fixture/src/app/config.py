import imp
import os

def load_plugin(path):
    return imp.load_source('plugin', path)

DEBUG = os.environ.get('APP_DEBUG') == '1'
