"""Password hashing (PBKDF2-HMAC-SHA256) and signed expiring bearer tokens (HMAC-SHA256)."""
import base64, hashlib, hmac, json, os, re, time
from .errors import AuthError, ValidationError
ITER = 200_000
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
_b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
_unb64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def normalize_email(email):
    e = (email or "").strip().lower()
    if not EMAIL_RE.match(e): raise ValidationError("invalid email")
    return e
def check_password_policy(pw):
    if not isinstance(pw, str) or not (10 <= len(pw) <= 200): raise ValidationError("password must be 10-200 characters")
def hash_password(pw, iterations=ITER):
    salt = os.urandom(16)
    return f"pbkdf2${iterations}${salt.hex()}${hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, iterations).hex()}"
def verify_password(pw, stored):
    try:
        _, it, salt, dk = stored.split("$")
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it)).hex(), dk)
    except (ValueError, AttributeError): return False
def make_token(secret, user_id, ttl=3600, now=None):
    body = _b64(json.dumps({"sub": user_id, "exp": int((now or time.time()) + ttl)}).encode())
    return body + "." + _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
def verify_token(secret, token, now=None):
    try:
        body, sig = token.split(".")
        good = _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, good): raise AuthError("invalid token")
        data = json.loads(_unb64(body))
        if data["exp"] < (now or time.time()): raise AuthError("token expired")
        return data["sub"]
    except AuthError: raise
    except Exception: raise AuthError("invalid token")
