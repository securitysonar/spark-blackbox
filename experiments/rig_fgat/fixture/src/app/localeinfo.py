import locale

def default_language():
    lang, _encoding = locale.getdefaultlocale()
    return lang
