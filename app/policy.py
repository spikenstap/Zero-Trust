from dataclasses import dataclass

from fastapi import HTTPException


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str


def authorize(user, action, resource=None) -> Decision:
    """Deny by default. Called for the route and each returned patient."""
    if not user:
        return Decision(False, "Требуется действительный токен")
    role = user["role"]
    if action == "me.read":
        return Decision(True, "Доступ к своему профилю")
    if action in {"audit.read", "demo.reset"}:
        return Decision(role == "admin", "Доступ администратора" if role == "admin" else "Только администратор")
    if action == "patients.list":
        allowed = role in {"doctor", "nurse", "patient"}
        return Decision(allowed, "Список фильтруется политикой" if allowed else "Администратор не имеет доступа к медицинским данным")
    if action == "patient.read":
        if role == "admin":
            return Decision(False, "Администратор не имеет доступа к медицинским данным")
        # Do not disclose whether a foreign/missing patient exists.
        if resource is None:
            return Decision(False, "Карта отсутствует или недоступна по политике")
        if role == "nurse":
            return Decision(True, "Только общие данные; диагноз и заметки скрыты")
        if role == "doctor" and resource.doctor_id == user["id"]:
            return Decision(True, "Пациент закреплён за этим врачом")
        if role == "patient" and resource.user_id == user["id"]:
            return Decision(True, "Доступ к собственной карте")
        return Decision(False, "Карта отсутствует или недоступна по политике")
    return Decision(False, "Действие не разрешено политикой")


def require_access(user, action, resource=None):
    """Repeat the authorization boundary at each sensitive handler."""
    if not user:
        raise HTTPException(401, "Требуется действительный токен")
    decision = authorize(user, action, resource)
    if not decision.allow:
        raise HTTPException(403, decision.reason)
    return user
