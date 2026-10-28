from fastapi import APIRouter, Request
from sqlalchemy import select

from .models import Patient, User
from .policy import authorize, require_access

router = APIRouter()
MASK = "•••••• (скрыто политикой)"


def serialize(patient, session, cipher, role, detail=False):
    doctor = session.get(User, patient.doctor_id)
    data = {"id": patient.id, "full_name": patient.full_name, "birth_date": patient.birth_date,
            "blood_group": patient.blood_group, "doctor_name": doctor.display_name,
            "doctor_username": doctor.username, "medical_fields_masked": role == "nurse"}
    if detail:
        # Nurse path never invokes decryption.
        data.update({field: MASK if role == "nurse" else cipher.decrypt(getattr(patient, field))
                     for field in ("diagnosis", "notes")})
    return data


@router.get("/api/patients")
async def patients(request: Request):
    require_access(getattr(request.state, "user", None), "patients.list")
    with request.app.state.db.Session() as session:
        return [serialize(p, session, request.app.state.cipher, request.state.user["role"])
                for p in session.scalars(select(Patient).order_by(Patient.id))
                if authorize(request.state.user, "patient.read", p).allow]


@router.get("/api/patients/{patient_id}")
async def patient(patient_id: int, request: Request):
    user = require_access(getattr(request.state, "user", None), "me.read")
    with request.app.state.db.Session() as session:
        record = session.get(Patient, patient_id)
        require_access(user, "patient.read", record)
        return serialize(record, session, request.app.state.cipher, user["role"], detail=True)
