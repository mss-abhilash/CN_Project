"""
Gateway Security Middleware
============================
FastAPI middleware that intercepts EVERY incoming request and runs it
through the 3-layer ACL engine before it reaches any endpoint handler.

Pipeline per request:
  1. Extract source IP from request
  2. Extract JWT token (if present) and decode it
  3. Determine device_id (if it's a device-auth request)
  4. Run ACLEngine.evaluate(ip, method, path, token, device_id)
  5. If DENY → return 403 immediately with reason
  6. If ALLOW → pass through to the endpoint

All denied requests are logged by the ACL engine to both
in-memory storage and persistent file (logs/acl_blocked.log).
"""

import json
import logging
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from gateway.acl_engine import ACLEngine, ACLAction
from backend.auth import decode_token

logger = logging.getLogger("security_middleware")


class GatewaySecurityMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware enforcing strict ACL-based access control.

    Injected into the app BEFORE any endpoint handler runs.
    Operates on raw HTTP — no authentication dependencies needed.
    """

    def __init__(self, app, acl_engine: ACLEngine):
        super().__init__(app)
        self.acl = acl_engine

    async def dispatch(self, request: Request, call_next):
        # ── 1. Extract source IP ──────────────────────────────────────
        source_ip = self._get_client_ip(request)

        method = request.method
        path = request.url.path

        # ── 2. Extract and decode JWT (if present) ────────────────────
        token_data = self._extract_token(request)

        # ── 3. Determine device_id for device-layer ACL ───────────────
        device_id = None
        if token_data and token_data.get("sub_type") == "device":
            device_id = token_data.get("sub")

        # ── 4. Run the ACL evaluation pipeline ────────────────────────
        verdict = self.acl.evaluate(
            source_ip=source_ip,
            method=method,
            path=path,
            token_data=token_data,
            device_id=device_id,
        )

        # ── 5. If denied → block immediately ──────────────────────────
        if not verdict.allowed:
            logger.warning(
                f"BLOCKED {method} {path} from {source_ip}: {verdict}"
            )
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Access denied by gateway ACL",
                    "reason": verdict.reason.value if verdict.reason else "Unknown",
                    "source_ip": source_ip,
                    "path": path,
                },
            )

        # ── 6. Allowed — pass through to handler ─────────────────────
        response = await call_next(request)
        return response

    def _get_client_ip(self, request: Request) -> str:
        """
        Extract the real client IP, respecting X-Forwarded-For
        for reverse-proxy deployments.
        """
        # Check X-Forwarded-For (set by reverse proxies / load balancers)
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # Take the first (leftmost) IP — the original client
            return forwarded.split(",")[0].strip()

        # Check X-Real-IP (nginx convention)
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()

        # Fallback to direct connection
        if request.client:
            return request.client.host

        return "0.0.0.0"

    def _extract_token(self, request: Request) -> Optional[dict]:
        """
        Extract and decode the JWT from the Authorization header.
        Returns the decoded payload dict, or None if absent/invalid.
        """
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return None

        token = auth_header[7:]  # Strip "Bearer "
        if not token:
            return None

        return decode_token(token)
