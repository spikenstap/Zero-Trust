import secrets

from passlib.context import CryptContext
from sqlalchemy import delete, select

from .models import AuditEvent, Patient, User

passwords = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto", pbkdf2_sha256__rounds=290000)


def seed(session, cipher, reset=False, commit=True):
    if reset:
        for model in (AuditEvent, Patient, User):
            session.execute(delete(model))
    elif session.scalar(select(User.id).limit(1)):
        return
    people = [
        ("doctor_aidar", "Айдар Омаров", "doctor"),
        ("doctor_sara", "Сара Алиева", "doctor"),
        ("nurse_aigul", "Айгуль Садыкова", "nurse"),
        ("patient_dana", "Дана Нурланова", "patient"),
        ("admin", "Администратор", "admin"),
    ]
    session.add_all([
        User(id=i, username=name, display_name=display, role=role,
             password_hash=passwords.hash("demo123"), token_version=secrets.token_hex(16))
        for i, (name, display, role) in enumerate(people, 1)
    ])
    session.flush()
    records = [
        ("Дана Нурланова", "1997-04-12", "A+", 1, 4, "Сезонная аллергия", "Плановый контроль. Учебная запись."),
        ("Тимур Асанов", "1988-08-03", "O+", 1, None, "Железодефицитная анемия", "Повторный приём. Учебная запись."),
        ("Лейла Маратова", "2001-11-21", "B+", 2, None, "Мигрень", "Ведение дневника самочувствия. Учебная запись."),
        ("Арман Беков", "1979-02-15", "AB+", 2, None, "Артериальная гипертензия", "Плановое наблюдение. Учебная запись."),
        ("Алия Серикова", "1993-06-07", "O−", 1, None, "Хронический гастрит", "Контрольный осмотр. Учебная запись."),
    ]
    for i, (name, birth, blood, doctor, user, diagnosis, notes) in enumerate(records, 1):
        session.add(Patient(id=i, full_name=name, birth_date=birth, blood_group=blood,
                            doctor_id=doctor, user_id=user, diagnosis=cipher.encrypt(diagnosis),
                            notes=cipher.encrypt(notes)))
    if commit:
        session.commit()
