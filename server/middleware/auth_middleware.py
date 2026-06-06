import time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        """Log request details and execution duration."""
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        print(f"[{request.method}] {request.url.path} - Status: {response.status_code} - Time: {process_time:.4f}s")
        return response

