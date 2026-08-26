import sys
import os

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.main import app as _fastapi_app

class VercelPathFixMiddleware:
    def __init__(self, asgi_app):
        self.asgi_app = asgi_app

    async def __call__(self, scope, receive, send):
        if scope.get("type") in ("http", "websocket"):
            headers = dict(scope.get("headers", []))
            # Vercel Edge Proxy sends original requested path in x-matched-path
            matched = (
                headers.get(b"x-matched-path", b"").decode("latin1", "ignore")
                or headers.get(b"x-vercel-matched-path", b"").decode("latin1", "ignore")
                or headers.get(b"x-forwarded-uri", b"").decode("latin1", "ignore")
            )
            if matched and not matched.startswith("/api/index"):
                scope["path"] = matched.split("?")[0]
            else:
                raw_path = scope.get("path", "")
                for prefix in ["/api/index.py", "/api/index", "/fastapi"]:
                    if raw_path.startswith(prefix):
                        clean = raw_path[len(prefix):]
                        scope["path"] = clean if clean.startswith("/") else ("/" + clean if clean else "/")
                        break
        await self.asgi_app(scope, receive, send)

app = VercelPathFixMiddleware(_fastapi_app)
handler = app
