import secrets

def new_session_id():
    return secrets.token_urlsafe(32)
