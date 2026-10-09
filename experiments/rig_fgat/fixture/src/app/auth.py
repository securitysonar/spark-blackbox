import hashlib

def token(user, secret):
    return hashlib.sha256(f'{user}:{secret}'.encode()).hexdigest()
