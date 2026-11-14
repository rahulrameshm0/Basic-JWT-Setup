import jwt
import datetime

SECRET_KEY = "this-is-a-much-longer-and-secure-secret-key-123!"  # 32+ chars

# CREATE token
def create_token(user_id):
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


# VERIFY token
def verify_token(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        return "Token expired"
    except jwt.InvalidTokenError:
        return "Invalid token"


token = create_token(user_id=42)
print("Token:", token)
print("Decoded:", verify_token(token))