from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Query, Request
from sqlalchemy import select

from .models import AuditEvent
from .policy import require_access

router = APIRouter()


def record_event(session, *, username, role, action, resource, result, status_code,
                 reason, request_id, simulated_night=False, app_timezone="Asia/Qyzylorda", now=None):
    now = now or datetime.now(timezone.utc)
    anomalies = []
    if result == "deny" and username != "anonymous":
        previous = session.scalars(select(AuditEvent).where(AuditEvent.username == username)
                                   .order_by(AuditEvent.id.desc()).limit(2)).all()
        if len(previous) == 2 and all(e.result == "deny" for e in previous):
            anomalies.append("3 и более отказа подряд")
    if status_code == 429:
        anomalies.append("Превышен лимит запросов")
    if simulated_night or 0 <= now.astimezone(ZoneInfo(app_timezone)).hour < 5:
        anomalies.append("Ночной доступ" + (" (имитация)" if simulated_night else ""))
    event = AuditEvent(timestamp=now.isoformat(), username=username, role=role, action=action,
                       resource=resource[:240], result=result, status_code=status_code, reason=reason,
                       suspicious=bool(anomalies), anomaly_reasons="; ".join(anomalies),
                       simulated_night=simulated_night, request_id=request_id)
    session.add(event)
    session.commit()
    return event


def finalize_denial(session, event, status_code):
    """Turn a pre-dispatch allow into the handler's actual denied outcome."""
    event.status_code = status_code
    event.result = "deny"
    event.reason = "Внутренняя ошибка обработчика" if status_code >= 500 else "Запрос отклонён обработчиком"
    previous = session.scalars(select(AuditEvent).where(
        AuditEvent.username == event.username, AuditEvent.id < event.id
    ).order_by(AuditEvent.id.desc()).limit(2)).all()
    if event.username != "anonymous" and len(previous) == 2 and all(e.result == "deny" for e in previous):
        label = "3 и более отказа подряд"
        if label not in event.anomaly_reasons:
            event.anomaly_reasons = "; ".join(filter(None, [event.anomaly_reasons, label]))
    event.suspicious = bool(event.anomaly_reasons)
    session.commit()


@router.get("/api/audit")
async def audit(request: Request, limit: int = Query(100, ge=1, le=500)):
    require_access(getattr(request.state, "user", None), "audit.read")
    with request.app.state.db.Session() as session:
        events = session.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)).all()
        return [{column.name: getattr(e, column.name) for column in AuditEvent.__table__.columns} for e in events]
