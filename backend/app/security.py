import base64, hashlib, hmac, os, secrets, time
import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

SECRET = os.getenv("JWT_SECRET") or secrets.token_urlsafe(48)  # set JWT_SECRET in production so tokens survive restarts
ALGO, TTL = "HS256", int(os.getenv("JWT_TTL_MINUTES", "120")) * 60
ITER = 240_000
bearer = HTTPBearer(auto_error=False)


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITER)
    return f"pbkdf2${ITER}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, it, salt, dk = stored.split("$")
        new = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt), int(it))
        return hmac.compare_digest(new, base64.b64decode(dk))
    except Exception:
        return False


def make_token(uid: str, role: str) -> str:
    return jwt.encode({"sub": uid, "role": role, "iat": int(time.time()), "exp": int(time.time()) + TTL}, SECRET, ALGO)


async def current_user(request: Request, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    if not cred:
        raise HTTPException(401, "Authentication required")
    try:
        data = jwt.decode(cred.credentials, SECRET, algorithms=[ALGO])
    except jwt.PyJWTError:
        raise HTTPException(401, "Session expired – please sign in again")
    user = await request.app.state.store.get_user(data["sub"])
    if not user:
        raise HTTPException(401, "Account not found")
    return user


async def admin_user(user=Depends(current_user)):
    if user.get("role") != "admin":
        raise HTTPException(403, "Administrator access required")
    return user
