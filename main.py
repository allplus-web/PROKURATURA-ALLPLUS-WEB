
import os
import re
import json
import time
import hmac
import hashlib
import base64

from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from passlib.context import CryptContext


# ---------- CONFIGURATION ----------

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./allplus.db")
DATABASE_URL = DATABASE_URL.replace(
    "postgres://", "postgresql://", 1
)

SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_THIS_BEFORE_DEPLOYMENT")
TOKEN_LIFETIME = 24 * 60 * 60

engine_options = {}
if DATABASE_URL.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_options)
SessionLocal = sessionmaker(
    bind=engine, autoflush=False, autocommit=False
)

Base = declarative_base()
passwords = CryptContext(schemes=["argon2"], deprecated="auto")
security = HTTPBearer(auto_error=False)

app = FastAPI(title="PROKURATURA ALLPLUS WEB")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


# ---------- DATABASE ----------

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(32), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(16), default="USER", nullable=False)
    status = Column(String(16), default="ACTIVE", nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------- TOKEN SYSTEM ----------

def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def create_token(user: User) -> str:
    payload = {
        "sub": user.id,
        "role": user.role,
        "exp": int(time.time()) + TOKEN_LIFETIME
    }

    body = b64encode(json.dumps(payload).encode())
    signature = hmac.new(
        SECRET_KEY.encode(), body.encode(), hashlib.sha256
    ).digest()

    return body + "." + b64encode(signature)


def read_token(token: str):
    try:
        body, signature = token.split(".", 1)

        expected = hmac.new(
            SECRET_KEY.encode(), body.encode(), hashlib.sha256
        ).digest()

        if not hmac.compare_digest(expected, b64decode(signature)):
            return None

        payload = json.loads(b64decode(body))

        if payload["exp"] < int(time.time()):
            return None

        return payload
    except Exception:
        return None


def current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
):
    if not credentials:
        raise HTTPException(401, "Требуется авторизация")

    payload = read_token(credentials.credentials)

    if not payload:
        raise HTTPException(401, "Сессия недействительна")

    user = db.query(User).filter(User.id == payload["sub"]).first()

    if not user or user.status != "ACTIVE":
        raise HTTPException(401, "Аккаунт недоступен")

    return user


def admin_only(user: User = Depends(current_user)):
    if user.role != "ADMIN":
        raise HTTPException(403, "Недостаточно прав")
    return user


# ---------- INPUT MODELS ----------

class RegisterData(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=128)


class LoginData(BaseModel):
    username: str
    password: str


# ---------- ADMIN SETUP ----------

def create_admin_from_environment():
    username = os.getenv("ADMIN_USERNAME")
    password = os.getenv("ADMIN_PASSWORD")

    if not username or not password:
        return

    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.username == username
        ).first()

        if not user:
            user = User(
                username=username,
                password_hash=passwords.hash(password),
                role="ADMIN",
                status="ACTIVE"
            )
            db.add(user)
        else:
            user.password_hash = passwords.hash(password)
            user.role = "ADMIN"
            user.status = "ACTIVE"

        db.commit()
    finally:
        db.close()


create_admin_from_environment()


# ---------- API ----------

@app.get("/health")
def health():
    return {"status": "online", "service": "ALLPLUS WEB"}


@app.post("/api/register")
def register(data: RegisterData, db: Session = Depends(get_db)):
    username = data.username.strip().lower()

    if not re.fullmatch(r"[a-z0-9_.-]+", username):
        raise HTTPException(
            400, "Логин: только латинские буквы, цифры, точка, дефис и _"
        )

    if db.query(User).filter(User.username == username).first():
        raise HTTPException(409, "Такой логин уже занят")

    user = User(
        username=username,
        password_hash=passwords.hash(data.password),
        role="USER",
        status="ACTIVE"
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "Регистрация успешна",
        "user_id": user.id,
        "username": user.username
    }


@app.post("/api/login")
def login(data: LoginData, db: Session = Depends(get_db)):
    username = data.username.strip().lower()

    user = db.query(User).filter(
        User.username == username
    ).first()

    if not user or not passwords.verify(data.password, user.password_hash):
        raise HTTPException(401, "Неверный логин или пароль")

    if user.status != "ACTIVE":
        raise HTTPException(403, "Аккаунт заблокирован")

    return {
        "access_token": create_token(user),
        "token_type": "bearer",
        "username": user.username,
        "role": user.role
    }


@app.get("/api/me")
def me(user: User = Depends(current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "status": user.status,
        "created_at": user.created_at.isoformat()
    }


@app.get("/api/admin/users")
def admin_users(
    admin: User = Depends(admin_only),
    db: Session = Depends(get_db)
):
    users = db.query(User).order_by(User.id.desc()).all()

    return {
        "total": len(users),
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "role": u.role,
                "status": u.status,
                "created_at": u.created_at.isoformat()
            }
            for u in users
        ]
    }
