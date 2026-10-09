import locale

def fmt(n):
    return locale.format('%d', n, grouping=True)
