def page(items, number, size=20):
    start = (number - 1) * size
    return items[start:start + size]
