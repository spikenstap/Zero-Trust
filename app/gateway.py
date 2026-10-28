import math
import re
import time
import uuid
from collections import defaultdict, deque

import jwt
from fastapi.responses import JSONResponse
from sqlalchemy import select
from starlette.middleware.base import BaseHTTPMiddleware
from starlette._utils import get_route_path

from .audit import finalize_denial, record_event
from .auth import public_user
from .models import AuditEvent, Patient, User
from .policy import authorize


class RateLimiter:
    """Sliding window; one process, serialized by gateway_lock."""
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.requests = defaultdict(deque)

    def check(self, username):
        now = self.clock()
        bucket = self.requests[username]
        while bucket and bucket[0] <= now - 10:
            bucket.popleft()
        if len(bucket) >= 10:
            return max(1, math.ceil(10 - (now - bucket[0])))
        bucket.append(now)
        return 0


def identify_action(method, path):
    routes = {("GET", "/api/me"): "me.read", ("GET", "/api/patients"): "patients.list",
              ("GET", "/api/audit"): "audit.read", ("POST", "/api/demo/reset"): "demo.reset"}
    if (method, path) in routes:
        return routes[(method, path)], None
    match = re.fullmatch(r"/api/patients/([1-9][0-9]{0,8})", path)
    if method == "GET" and match:
        return "patient.read", int(match.group(1))
    return "unknown", None


class Gateway(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Use exactly the router's ASGI path, never a URL reconstructed from Host.
        path = get_route_path(request.scope)
        if path != "/api" and not path.startswith("/api/"):
            return await call_next(request)
        async with request.app.state.gateway_lock:
            state = request.app.state
            request_id = str(uuid.uuid4())
            action, patient_id = identify_action(request.method, path)
            user = None
            status, retry = 200, 0
            reason = ""
            with state.db.Session() as session:
                header = request.headers.get("Authorization", "")
                scheme, _, token = header.partition(" ")
                try:
                    if scheme.lower() != "bearer" or not token or len(token) > 4096:
                        raise jwt.InvalidTokenError()
                    claims = jwt.decode(token, state.settings.jwt_secret, algorithms=["HS256"],
                                        options={"require": ["exp", "iat", "sub", "role", "ver"]})
                    account = session.scalar(select(User).where(User.username == claims["sub"]))
                    if not account or claims["role"] != account.role or claims["ver"] != account.token_version:
                        raise jwt.InvalidTokenError()
                    user = public_user(account)
                except jwt.ExpiredSignatureError:
                    status, reason = 401, "Срок действия токена истёк"
                except (jwt.InvalidTokenError, TypeError, ValueError):
                    status, reason = 401, "Токен отсутствует или недействителен"

                if user:
                    retry = state.limiter.check(user["username"])
                    if retry:
                        status, reason = 429, "Лимит: 10 запросов за 10 секунд на пользователя"
                    else:
                        resource = session.get(Patient, patient_id) if patient_id else None
                        decision = authorize(user, action, resource)
                        reason = decision.reason
                        if not decision.allow:
                            status = 403

                simulated = request.headers.get("X-Demo-Night") == "1"
                event = record_event(session, username=user["username"] if user else "anonymous",
                                     role=user["role"] if user else "unknown", action=action,
                                     resource=f"{request.method} {path}", result="allow" if status == 200 else "deny",
                                     status_code=status, reason=reason, request_id=request_id,
                                     simulated_night=simulated, app_timezone=state.settings.timezone)
                if status != 200:
                    response = JSONResponse({"detail": reason, "audit_id": event.id,
                                             "request_id": request_id, "suspicious": event.suspicious}, status_code=status)
                else:
                    request.state.user = user
                    request.state.audit_id = event.id
                    request.state.request_id = request_id
                    request.state.simulated_night = simulated
                    try:
                        response = await call_next(request)
                    except Exception:
                        # Keep exception details and encrypted/plain medical values out of responses.
                        response = JSONResponse({"detail": "Внутренняя ошибка обработчика",
                                                 "audit_id": event.id, "request_id": request_id}, status_code=500)
                    # reset clears history and recreates its own event in the same transaction.
                    if action == "demo.reset" and response.status_code == 200:
                        session.expire_all()
                        event = session.scalar(select(AuditEvent).where(AuditEvent.request_id == request_id))
                    elif response.status_code >= 400:
                        finalize_denial(session, event, response.status_code)
                response.headers["X-Audit-ID"] = str(request.state.audit_id if status == 200 else event.id)
                response.headers["X-Request-ID"] = request_id
                response.headers["X-Audit-Suspicious"] = str(event.suspicious).lower()
                if retry:
                    response.headers["Retry-After"] = str(retry)
                if status == 401:
                    response.headers["WWW-Authenticate"] = "Bearer"
                return response
