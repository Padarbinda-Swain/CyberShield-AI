import time
from collections import defaultdict, deque
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

LIMITS = {"/api/auth": (10, 60), "/api/scan": (30, 60), "default": (240, 60)}  # (requests, seconds) per client IP


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window limiter. For multi-instance deployments swap the dict for Redis (see docs/DEPLOYMENT.md)."""
    def __init__(self, app):
        super().__init__(app); self.hits = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        bucket = next((k for k in LIMITS if k != "default" and path.startswith(k)), "default")
        n, window = LIMITS[bucket]
        ip = (request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (request.client.host if request.client else "?"))
        q = self.hits[(ip, bucket)]; t = time.time()
        while q and q[0] < t - window: q.popleft()
        if len(q) >= n:
            return JSONResponse({"detail": "Too many requests – please slow down and retry shortly."}, 429, headers={"Retry-After": str(window)})
        q.append(t)
        return await call_next(request)
