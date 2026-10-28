from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(60), unique=True)
    display_name: Mapped[str] = mapped_column(String(100))
    role: Mapped[str] = mapped_column(String(20))
    password_hash: Mapped[str] = mapped_column(Text)
    token_version: Mapped[str] = mapped_column(String(40))


class Patient(Base):
    __tablename__ = "patients"
    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(String(100))
    birth_date: Mapped[str] = mapped_column(String(10))
    blood_group: Mapped[str] = mapped_column(String(8))
    doctor_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), unique=True, nullable=True)
    diagnosis: Mapped[str] = mapped_column(Text)
    notes: Mapped[str] = mapped_column(Text)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[str] = mapped_column(String(40))
    username: Mapped[str] = mapped_column(String(60), index=True)
    role: Mapped[str] = mapped_column(String(20))
    action: Mapped[str] = mapped_column(String(80))
    resource: Mapped[str] = mapped_column(String(240))
    result: Mapped[str] = mapped_column(String(5))
    status_code: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text)
    suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    anomaly_reasons: Mapped[str] = mapped_column(Text, default="")
    simulated_night: Mapped[bool] = mapped_column(Boolean, default=False)
    request_id: Mapped[str] = mapped_column(String(36), unique=True)
