import re

EMAIL = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

def is_email(value):
    return bool(EMAIL.match(value))
