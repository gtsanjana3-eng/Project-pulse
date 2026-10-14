class NotFound(Exception): pass
class BadTransition(Exception): pass
class ValidationError(ValueError): pass
class AuthError(Exception): pass
class Conflict(Exception): pass
class ConfigError(Exception): pass
class RateLimited(Exception):
    def __init__(self, retry_after): super().__init__("rate limit exceeded"); self.retry_after = retry_after
