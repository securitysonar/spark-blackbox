from collections import Counter

def top(items, n=3):
    return Counter(items).most_common(n)
