# File: main.py
# Mini CRM (FastAPI) — auth, contacts, CSV import/export, Google Maps geocoding, simple web UI.
# Designed for Render free tier (auto PORT), works locally too. SQLite by default.

from __future__ import annotations

import os
import csv
import io
import time
import threading
import datetime as dt
from typing import Optional, List, Annotated, Tuple, Dict, Any

import requests
from fastapi import (
    FastAPI, Depends, HTTPException, Query, Path, UploadFile, File, Form
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse, PlainTextResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, field_validator, EmailStr
from sqlalchemy import (
    create_engine, String, Integer, Boolean, DateTime, Text, Enum, ForeignKey,
    Float, func, select, Index, and_, or_, asc, desc
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session

# ---------------------------
# Env & Config
# ---------------------------

def _load_env_file() -> None:
    """Load simple KEY=VAL pairs from .env if present."""
    if os.path.exists(".env"):
        with open(".env", "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#") or "=" not in s:
                    continue
                k, v = s.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
_load_env_file()

JWT_SECRET = os.getenv("JWT_SECRET", "change-this-in-production")
JWT_ALG = "HS256"
JWT_EXPIRE_MIN = int(os.getenv("JWT_EXPIRE_MIN", "1440"))  # 24h
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./crm.db")
GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY", "")
PORT = int(os.getenv("PORT", "10000"))  # Render default; works locally too

# ---------------------------
# Database
# ---------------------------

class Base(DeclarativeBase):
    pass

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# ---------------------------
# Models
# ---------------------------

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(255))
    hashed_password: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    contacts: Mapped[List["Contact"]] = relationship(back_populates="owner", cascade="all, delete-orphan")

class Contact(Base):
    __tablename__ = "contacts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    first_name: Mapped[str] = mapped_column(String(120), index=True)
    last_name: Mapped[str] = mapped_column(String(120), index=True)
    email: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    phone: Mapped[Optional[str]] = mapped_column(String(40), index=True)
    company: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    position: Mapped[Optional[str]] = mapped_column(String(255))
    notes: Mapped[Optional[str]] = mapped_column(Text)
    address_line1: Mapped[Optional[str]] = mapped_column(String(255))
    address_line2: Mapped[Optional[str]] = mapped_column(String(255))
    city: Mapped[Optional[str]] = mapped_column(String(120), index=True)
    state: Mapped[Optional[str]] = mapped_column(String(120), index=True)
    postal_code: Mapped[Optional[str]] = mapped_column(String(40), index=True)
    country: Mapped[Optional[str]] = mapped_column(String(120), index=True)
    latitude: Mapped[Optional[float]] = mapped_column(Float, index=True)
    longitude: Mapped[Optional[float]] = mapped_column(Float, index=True)
    last_contacted_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))
    next_follow_up_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    owner: Mapped[User] = relationship(back_populates="contacts")

Index("ix_contacts_name", Contact.first_name, Contact.last_name)
Index("ix_contacts_company_email", Contact.company, Contact.email)
InteractionKind = Enum("call", "email", "meeting", "note", name="interaction_kind")

class Interaction(Base):
    __tablename__ = "interactions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    contact_id: Mapped[int] = mapped_column(ForeignKey("contacts.id", ondelete="CASCADE"), index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(InteractionKind)
    summary: Mapped[str] = mapped_column(Text)
    occurred_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=func.now(), index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

# ---------------------------
# Schemas
# ---------------------------

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str

    @field_validator("password")
    def strong(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("password too short")
        return v

class UserOut(BaseModel):
    id: int
    email: EmailStr
    full_name: str
    is_active: bool
    is_admin: bool
    created_at: dt.datetime

class ContactCreate(BaseModel):
    first_name: str
    last_name: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    company: Optional[str] = None
    position: Optional[str] = None
    notes: Optional[str] = None
    next_follow_up_at: Optional[dt.datetime] = None
    address_line1: Optional[str] = None
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None

class ContactUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    company: Optional[str] = None
    position: Optional[str] = None
    notes: Optional[str] = None
    last_contacted_at: Optional[dt.datetime] = None
    next_follow_up_at: Optional[dt.datetime] = None
    address_line1: Optional[str] = None
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None

class ContactOut(BaseModel):
    id: int
    first_name: str
    last_name: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    company: Optional[str] = None
    position: Optional[str] = None
    notes: Optional[str] = None
    address_line1: Optional[str] = None
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    last_contacted_at: Optional[dt.datetime] = None
    next_follow_up_at: Optional[dt.datetime] = None
    created_at: dt.datetime
    updated_at: dt.datetime

class InteractionCreate(BaseModel):
    kind: str
    summary: str
    occurred_at: Optional[dt.datetime] = None

class InteractionOut(BaseModel):
    id: int
    contact_id: int
    kind: str
    summary: str
    occurred_at: dt.datetime
    created_at: dt.datetime

class PageMeta(BaseModel):
    total: int
    limit: int
    offset: int

class ContactPage(BaseModel):
    data: List[ContactOut]
    meta: PageMeta

class InteractionPage(BaseModel):
    data: List[InteractionOut]
    meta: PageMeta

# ---------------------------
# Auth utils & dependencies
# ---------------------------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def create_access_token(subject: str, expires_minutes: int = JWT_EXPIRE_MIN) -> str:
    now = dt.datetime.utcnow()
    exp = now + dt.timedelta(minutes=expires_minutes)
    payload = {"sub": subject, "iat": int(now.timestamp()), "exp": int(exp.timestamp())}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        sub = payload.get("sub")
        if not sub:
            raise JWTError("Missing sub")
        return str(sub)
    except JWTError as e:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from e

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
DB = Annotated[Session, Depends(get_db)]

TokenDep = Annotated[str, Depends(oauth2_scheme)]

def get_current_user(token: TokenDep, db: DB) -> User:
    email = decode_token(token)
    user = db.scalar(select(User).where(User.email == email))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user

CurrentUser = Annotated[User, Depends(get_current_user)]

# ---------------------------
# App
# ---------------------------

app = FastAPI(title="Mini CRM (No‑Code + CSV + Maps)", version="1.4.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"]
)

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

# ---------------------------
# Auth endpoints
# ---------------------------

@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: UserCreate, db: DB):
    if db.scalar(select(User).where(User.email == payload.email)):
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserOut(
        id=user.id, email=user.email, full_name=user.full_name,
        is_active=user.is_active, is_admin=user.is_admin, created_at=user.created_at
    )

@app.post("/auth/login", response_model=Token)
def login(form: Annotated[OAuth2PasswordRequestForm, Depends()], db: DB):
    user = db.scalar(select(User).where(User.email == form.username))
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    return Token(access_token=create_access_token(subject=user.email))

@app.get("/auth/me", response_model=UserOut)
def me(current: CurrentUser):
    return UserOut(
        id=current.id, email=current.email, full_name=current.full_name,
        is_active=current.is_active, is_admin=current.is_admin, created_at=current.created_at
    )

# ---------------------------
# Contacts endpoints
# ---------------------------

_SORT_MAP = {
    "created_at": Contact.created_at,
    "updated_at": Contact.updated_at,
    "next_follow_up_at": Contact.next_follow_up_at,
    "last_contacted_at": Contact.last_contacted_at,
    "first_name": Contact.first_name,
    "last_name": Contact.last_name,
    "company": Contact.company,
    "city": Contact.city,
    "state": Contact.state,
}

def to_contact_out(c: Contact) -> ContactOut:
    return ContactOut(
        id=c.id, first_name=c.first_name, last_name=c.last_name, email=c.email, phone=c.phone,
        company=c.company, position=c.position, notes=c.notes,
        address_line1=c.address_line1, address_line2=c.address_line2, city=c.city, state=c.state,
        postal_code=c.postal_code, country=c.country, latitude=c.latitude, longitude=c.longitude,
        last_contacted_at=c.last_contacted_at, next_follow_up_at=c.next_follow_up_at,
        created_at=c.created_at, updated_at=c.updated_at,
    )

@app.post("/contacts", response_model=ContactOut, status_code=201)
def create_contact(payload: ContactCreate, db: DB, current: CurrentUser):
    c = Contact(owner_id=current.id, **payload.dict())
    db.add(c)
    db.commit()
    db.refresh(c)
    return to_contact_out(c)

@app.get("/contacts", response_model=ContactPage)
def list_contacts(
    db: DB, current: CurrentUser,
    q: Optional[str] = Query(None),
    company: Optional[str] = Query(None),
    city: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    sort_by: str = Query("updated_at", enum=list(_SORT_MAP.keys())),
    sort_dir: str = Query("desc", enum=["asc", "desc"]),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    base = select(Contact).where(Contact.owner_id == current.id)
    if q:
        like = f"%{q.strip()}%"
        base = base.where(or_(
            Contact.first_name.ilike(like), Contact.last_name.ilike(like),
            Contact.email.ilike(like), Contact.phone.ilike(like),
            Contact.company.ilike(like), Contact.address_line1.ilike(like),
            Contact.city.ilike(like), Contact.state.ilike(like),
            Contact.postal_code.ilike(like), Contact.country.ilike(like),
        ))
    if company: base = base.where(Contact.company == company)
    if city: base = base.where(Contact.city == city)
    if state: base = base.where(Contact.state == state)

    base = base.order_by(asc(_SORT_MAP[sort_by]) if sort_dir == "asc" else desc(_SORT_MAP[sort_by]))
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = db.scalars(base.limit(limit).offset(offset)).all()
    return ContactPage(data=[to_contact_out(c) for c in rows], meta=PageMeta(total=total, limit=limit, offset=offset))

@app.get("/contacts/{contact_id}", response_model=ContactOut)
def get_contact(
    contact_id: int = Path(..., ge=1),
    db: DB = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    c = db.scalar(select(Contact).where(and_(Contact.id == contact_id, Contact.owner_id == current.id)))
    if not c:
        raise HTTPException(status_code=404, detail="Contact not found")
    return to_contact_out(c)

@app.put("/contacts/{contact_id}", response_model=ContactOut)
def update_contact(contact_id: int, payload: ContactUpdate, db: DB, current: CurrentUser):
    c = db.scalar(select(Contact).where(and_(Contact.id == contact_id, Contact.owner_id == current.id)))
    if not c:
        raise HTTPException(status_code=404, detail="Contact not found")
    for k, v in payload.dict(exclude_unset=True).items():
        setattr(c, k, v)
    c.updated_at = func.now()
    db.add(c)
    db.commit()
    db.refresh(c)
    return to_contact_out(c)

@app.delete("/contacts/{contact_id}", status_code=204)
def delete_contact(contact_id: int, db: DB, current: CurrentUser):
    c = db.scalar(select(Contact).where(and_(Contact.id == contact_id, Contact.owner_id == current.id)))
    if not c:
        raise HTTPException(status_code=404, detail="Contact not found")
    db.delete(c)
    db.commit()
    return JSONResponse(status_code=204, content=None)

# ---------------------------
# Interactions endpoints
# ---------------------------

class Interaction(Base):  # keep ORMs grouped above; this class defined earlier, reused here.
    ...

def to_inter_out(i: Interaction) -> InteractionOut:
    return InteractionOut(
        id=i.id, contact_id=i.contact_id, kind=i.kind, summary=i.summary,
        occurred_at=i.occurred_at, created_at=i.created_at,
    )

@app.post("/contacts/{contact_id}/interactions", response_model=InteractionOut, status_code=201)
def create_interaction(contact_id: int, payload: InteractionCreate, db: DB, current: CurrentUser):
    c = db.scalar(select(Contact).where(and_(Contact.id == contact_id, Contact.owner_id == current.id)))
    if not c:
        raise HTTPException(status_code=404, detail="Contact not found")
    if payload.kind not in ("call", "email", "meeting", "note"):
        raise HTTPException(status_code=400, detail="Invalid kind")
    when = payload.occurred_at or dt.datetime.utcnow()
    i = Interaction(contact_id=c.id, owner_id=current.id, kind=payload.kind, summary=payload.summary, occurred_at=when)
    c.last_contacted_at = when
    db.add_all([i, c])
    db.commit()
    db.refresh(i)
    return to_inter_out(i)

@app.get("/contacts/{contact_id}/interactions", response_model=InteractionPage)
def list_interactions(
    contact_id: int, db: DB, current: CurrentUser,
    limit: int = Query(20, ge=1, le=200), offset: int = Query(0, ge=0)
):
    c = db.scalar(select(Contact).where(and_(Contact.id == contact_id, Contact.owner_id == current.id)))
    if not c:
        raise HTTPException(status_code=404, detail="Contact not found")
    base = select(Interaction).where(Interaction.contact_id == c.id).order_by(desc(Interaction.occurred_at))
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = db.scalars(base.limit(limit).offset(offset)).all()
    return InteractionPage(data=[to_inter_out(x) for x in rows], meta=PageMeta(total=total, limit=limit, offset=offset))

@app.delete("/interactions/{interaction_id}", status_code=204)
def delete_interaction(interaction_id: int, db: DB, current: CurrentUser):
    i = db.scalar(select(Interaction).where(and_(Interaction.id == interaction_id, Interaction.owner_id == current.id)))
    if not i:
        raise HTTPException(status_code=404, detail="Interaction not found")
    db.delete(i)
    db.commit()
    return JSONResponse(status_code=204, content=None)

# ---------------------------
# Geocoding
# ---------------------------

def build_full_address(c: Contact) -> Optional[str]:
    parts = [c.address_line1, c.address_line2, c.city, c.state, c.postal_code, c.country]
    s = ", ".join(p for p in parts if p and p.strip())
    return s or None

def google_geocode(address: str) -> Tuple[float, float]:
    if not GOOGLE_MAPS_API_KEY:
        raise HTTPException(status_code=400, detail="GOOGLE_MAPS_API_KEY not set")
    url = "https://maps.googleapis.com/maps/api/geocode/json"
    resp = requests.get(url, params={"address": address, "key": GOOGLE_MAPS_API_KEY}, timeout=10)
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Geocoding upstream error: {resp.status_code
"main:app", host="0.0.0.0", port=PORT)
