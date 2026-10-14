import os
from dataclasses import dataclass
from .errors import ConfigError

def load_dotenv(path=None, environ=os.environ):
    """Minimal .env reader (KEY=VALUE, # comments, optional quotes). Never overrides variables already set."""
    candidates = [path] if path else [os.environ.get("PP_ENV_FILE"), ".env", os.path.join("..", ".env")]
    for c in candidates:
        if c and os.path.isfile(c):
            with open(c, encoding="utf-8-sig") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line: continue
                    k, v = line.split("=", 1); k, v = k.strip(), v.strip()
                    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'": v = v[1:-1]
                    environ.setdefault(k, v)
            return c
    return None

@dataclass(frozen=True)
class Settings:
    secret: str
    db_path: str = "projectpulse.db"
    env: str = "development"
    cors_origins: tuple = ("http://localhost:5173",)
    max_projects_per_user: int = 25
    audits_per_hour: int = 10
    logins_per_15min: int = 10
    axe_path: str | None = None
    browser_no_sandbox: bool = False
    @classmethod
    def from_env(cls, environ=os.environ):
        secret = environ.get("PP_SECRET", "")
        if len(secret) < 32:
            raise ConfigError("PP_SECRET must be at least 32 chars. Generate: python -c \"import secrets;print(secrets.token_urlsafe(48))\"")
        origins = tuple(o.strip() for o in environ.get("PP_CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip())
        if "*" in origins: raise ConfigError("PP_CORS_ORIGINS must list explicit origins, not '*'")
        return cls(secret=secret, db_path=environ.get("PP_DB_PATH", "projectpulse.db"), env=environ.get("PP_ENV", "development"),
                   cors_origins=origins, max_projects_per_user=int(environ.get("PP_MAX_PROJECTS", 25)),
                   audits_per_hour=int(environ.get("PP_AUDITS_PER_HOUR", 10)), logins_per_15min=int(environ.get("PP_LOGINS_PER_15MIN", 10)),
                   axe_path=environ.get("PP_AXE_PATH") or None, browser_no_sandbox=environ.get("PP_BROWSER_NO_SANDBOX") == "1")
