import shutil

def _ignore(func, path, exc_info):
    pass

def remove_tree(path):
    shutil.rmtree(path, onerror=_ignore)
