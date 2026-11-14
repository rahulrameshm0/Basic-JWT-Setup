import datetime
import os
import secrets

import jwt

# Never hardcode a signing key. Set JWT_SECRET_KEY in your environment.
# Without it we generate an ephemeral key, which is fine for a demo:
# tokens simply stop verifying once the process exits.
SECRET_KEY = os.environ.get("JWT_SECRET_KEY") or secrets.token_hex(32)

ALGORITHM = "HS256"
TOKEN_TTL = datetime.timedelta(hours=1)


# CREATE token
def create_token(user_id, ttl=TOKEN_TTL):
    now = datetime.datetime.now(datetime.UTC)
    payload = {
        "sub": str(user_id),  # standard "subject" claim; must be a string
        "iat": now,           # issued at
        "exp": now + ttl,     # expiry - PyJWT rejects the token after this
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# VERIFY token
def verify_token(token):
    """Return the decoded payload, or raise a jwt.InvalidTokenError subclass."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


if __name__ == "__main__":
    token = create_token(user_id=42)
    print("Token:", token)

    try:
        claims = verify_token(token)
    except jwt.ExpiredSignatureError:
        print("Decoded: Token expired")
    except jwt.InvalidTokenError:
        print("Decoded: Invalid token")
    else:
        print("Decoded:", claims)

    # An already-expired token should be rejected.
    expired = create_token(user_id=42, ttl=datetime.timedelta(seconds=-1))
    try:
        verify_token(expired)
    except jwt.ExpiredSignatureError:
        print("Expired token: rejected")
    except jwt.InvalidTokenError:
        print("Expired token: rejected (invalid)")

    # A token signed with a different key should be rejected.
    other_key = "an-attacker-key-that-is-also-32-bytes-long"
    forged = jwt.encode({"sub": "1"}, other_key, algorithm=ALGORITHM)
    try:
        verify_token(forged)
    except jwt.InvalidTokenError:
        print("Forged token: rejected")
