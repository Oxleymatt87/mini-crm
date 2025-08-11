# File: main.py
# Mini CRM (FastAPI) — auth, contacts, CSV import/export, Google Maps geocoding, simple web UI.
# Works locally and on Render free tier (auto-detects PORT).

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
    FastAPI, Depends, HTTPException, Query, Path, UploadFile, File, Form, Response
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
JWT_EXPIRE_MIN = int(os.getenv("JWT_EXPIRE_MIN", "1440"))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./crm.db")
GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY", "")
PORT = int(os.getenv("PORT", "10000"))

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

app = FastAPI(title="Mini CRM (No‑Code + CSV + Maps)", version="1.5.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"]
)

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

@app.get("/health")
def health():
    return {"ok": True}

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
def get_contact(contact_id: int, db: DB, current: CurrentUser):
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
    return Response(status_code=204)

# ---------------------------
# Interactions endpoints
# ---------------------------

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
    return Response(status_code=204)

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
        raise HTTPException(status_code=502, detail=f"Geocoding upstream error: {resp.status_code}")
    data = resp.json()
    if data.get("status") != "OK" or not data.get("results"):
        raise HTTPException(status_code=404, detail=f"Geocoding failed: {data.get('status')}")
    loc = data["results"][0]["geometry"]["location"]
    return float(loc["lat"]), float(loc["lng"])

@app.post("/contacts/{contact_id}/geocode", response_model=ContactOut)
def geocode_contact(contact_id: int, db: DB, current: CurrentUser):
    c = db.scalar(select(Contact).where(and_(Contact.id == contact_id, Contact.owner_id == current.id)))
    if not c:
        raise HTTPException(status_code=404, detail="Contact not found")
    full_addr = build_full_address(c)
    if not full_addr:
        raise HTTPException(status_code=400, detail="Contact missing address fields")
    lat, lng = google_geocode(full_addr)
    c.latitude, c.longitude, c.updated_at = lat, lng, func.now()
    db.add(c)
    db.commit()
    db.refresh(c)
    return to_contact_out(c)

@app.post("/contacts/geocode_missing", response_model=ContactPage)
def geocode_missing(db: DB, current: CurrentUser, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    if not GOOGLE_MAPS_API_KEY:
        raise HTTPException(status_code=400, detail="GOOGLE_MAPS_API_KEY not set")
    base = (
        select(Contact)
        .where(and_(Contact.owner_id == current.id, or_(Contact.latitude.is_(None), Contact.longitude.is_(None))))
        .order_by(Contact.id.asc())
    )
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = db.scalars(base.limit(limit).offset(offset)).all()
    updated: List[Contact] = []
    for c in rows:
        full_addr = build_full_address(c)
        if not full_addr:
            continue
        try:
            lat, lng = google_geocode(full_addr)
            c.latitude, c.longitude, c.updated_at = lat, lng, func.now()
            db.add(c)
            updated.append(c)
        except HTTPException:
            continue
    db.commit()
    return ContactPage(data=[to_contact_out(c) for c in updated], meta=PageMeta(total=total, limit=limit, offset=offset))

# ---------------------------
# CSV import/export
# ---------------------------

CSV_FIELDS = [
    "first_name","last_name","email","phone","company","position","notes",
    "address_line1","address_line2","city","state","postal_code","country","latitude","longitude"
]

HEADER_MAP: Dict[str, str] = {
    "first":"first_name","firstname":"first_name","first name":"first_name","given name":"first_name",
    "last":"last_name","lastname":"last_name","last name":"last_name","surname":"last_name",
    "mail":"email","e-mail":"email","mobile":"phone","phone number":"phone","telephone":"phone",
    "company name":"company","org":"company","organization":"company",
    "job":"position","title":"position","role":"position",
    "address":"address_line1","street":"address_line1","addr1":"address_line1","addr2":"address_line2",
    "zip":"postal_code","zipcode":"postal_code","post code":"postal_code",
    "country/region":"country","lat":"latitude","lng":"longitude","long":"longitude",
}

def _normalize_header(s: str) -> str:
    return s.strip().lower().replace("_"," ")

def _map_headers(headers: List[str]) -> List[str]:
    mapped: List[str] = []
    for h in headers:
        key = _normalize_header(h)
        if key in HEADER_MAP:
            mapped.append(HEADER_MAP[key]); continue
        key2 = key.replace(" ", "_")
        if key2 in CSV_FIELDS:
            mapped.append(key2); continue
        if key in CSV_FIELDS:
            mapped.append(key); continue
        mapped.append("__skip__")
    return mapped

@app.get("/contacts/export_csv")
def export_csv(db: DB, current: CurrentUser):
    def row_iter():
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(CSV_FIELDS); yield out.getvalue(); out.seek(0); out.truncate(0)
        q = select(Contact).where(Contact.owner_id == current.id).order_by(Contact.id.asc())
        for c in db.scalars(q).all():
            w.writerow([
                c.first_name, c.last_name, c.email, c.phone, c.company, c.position, c.notes,
                c.address_line1, c.address_line2, c.city, c.state, c.postal_code, c.country,
                c.latitude, c.longitude
            ])
            yield out.getvalue(); out.seek(0); out.truncate(0)
    filename = f"contacts_{dt.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(row_iter(), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})

@app.get("/contacts/template_csv", response_class=PlainTextResponse)
def template_csv():
    return ",".join(CSV_FIELDS) + "\n"

@app.post("/contacts/import_csv")
async def import_csv(
    db: DB, current: CurrentUser, file: UploadFile = File(...),
    upsert: bool = Form(True), dry_run: bool = Form(False),
    encoding: str = Form("utf-8"), delimiter: str = Form(","),
):
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(400, "CSV too large (>5MB)")
    try:
        text = content.decode(encoding, errors="replace")
    except Exception:
        raise HTTPException(400, f"Bad encoding: {encoding}")
    reader = csv.reader(io.StringIO(text), delimiter=delimiter or ",")
    try:
        headers = next(reader)
    except StopIteration:
        raise HTTPException(400, "Empty CSV")
    colmap = _map_headers(headers)

    created = updated = skipped = 0
    samples: List[Dict[str, Any]] = []

    def find_existing(row: Dict[str, Any]) -> Optional[Contact]:
        if row.get("email"):
            ex = db.scalar(select(Contact).where(and_(Contact.owner_id==current.id, Contact.email==row["email"])))
            if ex: return ex
        if row.get("first_name") and row.get("last_name") and row.get("company"):
            ex2 = db.scalar(select(Contact).where(and_(
                Contact.owner_id==current.id,
                Contact.first_name==row["first_name"],
                Contact.last_name==row["last_name"],
                Contact.company==row["company"]
            )))
            if ex2: return ex2
        return None

    for r in reader:
        data: Dict[str, Any] = {}
        for idx, val in enumerate(r):
            key = colmap[idx] if idx < len(colmap) else "__skip__"
            if key == "__skip__": continue
            v = val.strip()
            if key in ("latitude","longitude"):
                data[key] = float(v) if v else None
            else:
                data[key] = v or None

        if not data.get("first_name") and not data.get("email"):
            skipped += 1; continue

        existing = find_existing(data) if upsert else None

        if dry_run:
            samples.append({"action": "update" if existing else "create", "data": data})
            continue

        if existing:
            for k,v in data.items(): setattr(existing, k, v)
            existing.updated_at = func.now(); db.add(existing); updated += 1
        else:
            c = Contact(owner_id=current.id, **{k:v for k,v in data.items() if k in CSV_FIELDS or k in ("position","notes")})
            db.add(c); created += 1

    if not dry_run:
        db.commit()
    return {"ok": True, "summary": {"created": created, "updated": updated, "skipped": skipped, "dry_run": dry_run, "upsert": upsert}, "samples": samples[:10], "mapped_headers": colmap}

# ---------------------------
# UI pages
# ---------------------------

@app.get("/", response_class=HTMLResponse)
def home():
    map_status = "✅" if GOOGLE_MAPS_API_KEY else "⚠️"
    note = "" if GOOGLE_MAPS_API_KEY else " (Map needs GOOGLE_MAPS_API_KEY in Render → Environment)"
    return HTMLResponse(f"""
<!doctype html><html><head><meta charset="utf-8"><title>Mini CRM</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{{font-family:system-ui,sans-serif;margin:0}} header,footer{{padding:16px}} main{{padding:16px}} a.button{{display:inline-block;padding:10px 14px;border:1px solid #ccc;border-radius:8px;text-decoration:none}}</style>
</head><body>
<header><h2>Mini CRM (No‑Code + CSV + Maps)</h2></header>
<main>
  <p><a class="button" href="/app">Open App</a> &nbsp; <a class="button" href="/docs">API Docs</a> &nbsp; <a class="button" href="/map">Map</a> {map_status}{note}</p>
</main>
<footer><small>Hosted on Render. Data in <code>crm.db</code> (SQLite) unless you switch to Postgres.</small></footer>
</body></html>
""")

@app.get("/app", response_class=HTMLResponse)
def app_page():
    return HTMLResponse("""
<!doctype html>
<html>
<head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Mini CRM App</title>
<style>
  :root{--pad:12px}
  *{box-sizing:border-box} body{font-family:system-ui,Segoe UI,Arial;margin:0}
  header{padding:var(--pad);border-bottom:1px solid #ddd;display:flex;gap:10px;align-items:center}
  main{padding:var(--pad)} input,select,button,textarea{padding:8px;margin:4px 0} .row{display:flex;gap:12px;flex-wrap:wrap}
  table{border-collapse:collapse;width:100%;margin-top:12px} th,td{border:1px solid #eee;padding:8px;text-align:left}
  .card{border:1px solid #ddd;border-radius:8px;padding:var(--pad);margin:var(--pad) 0}
  .actions{display:flex;gap:8px;flex-wrap:wrap}
  .right{margin-left:auto}
</style>
</head>
<body>
<header>
  <strong>Mini CRM</strong>
  <span class="right">
    <a href="/contacts/export_csv" id="btn-export" download>Export CSV</a>
    <button id="btn-import">Import CSV</button>
    <input type="file" id="file" accept=".csv" style="display:none"/>
    <button id="btn-logout">Logout</button>
    <a href="/map" target="_blank">Open Map</a>
  </span>
</header>
<main>
  <div id="auth" class="card">
    <h3>1) Create account or login</h3>
    <div class="row">
      <div>
        <h4>Register</h4>
        <input id="reg_name" placeholder="Full name"/>
        <input id="reg_email" placeholder="Email"/>
        <input id="reg_pass" type="password" placeholder="Password (min 6)"/>
        <div><button id="btn-register">Register</button></div>
      </div>
      <div>
        <h4>Login</h4>
        <input id="log_email" placeholder="Email"/>
        <input id="log_pass" type="password" placeholder="Password"/>
        <div><button id="btn-login">Login</button></div>
      </div>
    </div>
    <div id="me"></div>
  </div>

  <div id="contacts" class="card" style="display:none">
    <h3>2) Contacts</h3>
    <div class="row">
      <input id="q" placeholder="Search name/email/company/city/state"/>
      <button id="btn-search">Search</button>
      <button id="btn-new">New Contact</button>
      <button id="btn-refresh">Refresh</button>
      <a href="/contacts/template_csv" target="_blank">Template CSV</a>
    </div>
    <div id="editor" style="display:none">
      <h4 id="ed-title">New Contact</h4>
      <div class="row">
        <input id="ed_first" placeholder="First name"/>
        <input id="ed_last" placeholder="Last name"/>
        <input id="ed_email" placeholder="Email"/>
        <input id="ed_phone" placeholder="Phone"/>
        <input id="ed_company" placeholder="Company"/>
        <input id="ed_position" placeholder="Position"/>
        <input id="ed_addr1" placeholder="Address line 1"/>
        <input id="ed_addr2" placeholder="Address line 2"/>
        <input id="ed_city" placeholder="City"/>
        <input id="ed_state" placeholder="State"/>
        <input id="ed_zip" placeholder="Postal code"/>
        <input id="ed_country" placeholder="Country"/>
      </div>
      <textarea id="ed_notes" rows="3" placeholder="Notes"></textarea>
      <div class="actions">
        <button id="btn-save">Save</button>
        <button id="btn-cancel">Cancel</button>
      </div>
      <input type="hidden" id="ed_id"/>
    </div>
    <table id="grid">
      <thead><tr>
        <th>Name</th><th>Company</th><th>City</th><th>State</th><th>Email</th><th>Phone</th><th>Geo</th><th>Actions</th>
      </tr></thead>
      <tbody></tbody>
    </table>
  </div>
</main>

<script>
const api = {
  token(){ return localStorage.getItem("jwt") || "" },
  setToken(t){ t?localStorage.setItem("jwt", t):localStorage.removeItem("jwt") },
  headers(json=true){ const h = json?{"Content-Type":"application/json"}:{}; const t=this.token(); if(t) h["Authorization"]="Bearer "+t; return h },
  async register(name,email,pass){ const r=await fetch("/auth/register",{method:"POST",headers:this.headers(),body:JSON.stringify({full_name:name,email,password:pass})}); if(!r.ok) throw new Error(await r.text()); return r.json() },
  async login(email,pass){ const f=new URLSearchParams(); f.set("username",email); f.set("password",pass); const r=await fetch("/auth/login",{method:"POST",body:f}); if(!r.ok) throw new Error(await r.text()); return r.json() },
  async me(){ const r=await fetch("/auth/me",{headers:this.headers()}); if(!r.ok) return null; return r.json() },
  async list(q=""){ const u = new URL("/contacts", window.location.origin); if(q) u.searchParams.set("q", q); u.searchParams.set("limit","500"); const r=await fetch(u,{headers:this.headers()}); if(!r.ok) throw new Error(await r.text()); return r.json() },
  async create(c){ const r=await fetch("/contacts",{method:"POST",headers:this.headers(),body:JSON.stringify(c)}); if(!r.ok) throw new Error(await r.text()); return r.json() },
  async update(id,c){ const r=await fetch("/contacts/"+id,{method:"PUT",headers:this.headers(),body:JSON.stringify(c)}); if(!r.ok) throw new Error(await r.text()); return r.json() },
  async remove(id){ const r=await fetch("/contacts/"+id,{method:"DELETE",headers:this.headers()}); if(!r.ok) throw new Error(await r.text()) },
  async geocode(id){ const r=await fetch(`/contacts/${id}/geocode`,{method:"POST",headers:this.headers()}); if(!r.ok) throw new Error(await r.text()); return r.json() },
  async importCSV(file, upsert=true, dry=false){ const fd=new FormData(); fd.append("file", file); fd.append("upsert", String(upsert)); fd.append("dry_run", String(dry)); const r=await fetch("/contacts/import_csv",{method:"POST",headers:this.headers(false),body:fd}); if(!r.ok) throw new Error(await r.text()); return r.json() },
};
const $ = (id)=>document.getElementById(id);
function toast(m){ alert(m); }

async function refreshMe(){
  const me = await api.me();
  if(me){ $("me").textContent = `Logged in as ${me.full_name} (${me.email})`; $("contacts").style.display = ""; }
  else { $("me").textContent = "Not logged in."; $("contacts").style.display = "none"; }
}
function clearEditor(){ ["ed_id","ed_first","ed_last","ed_email","ed_phone","ed_company","ed_position","ed_addr1","ed_addr2","ed_city","ed_state","ed_zip","ed_country","ed_notes"].forEach(id=>$(id).value=""); }
function openEditor(c=null){
  $("editor").style.display=""; $("ed-title").textContent=c?"Edit Contact":"New Contact";
  if(c){ $("ed_id").value=c.id; $("ed_first").value=c.first_name||""; $("ed_last").value=c.last_name||""; $("ed_email").value=c.email||""; $("ed_phone").value=c.phone||""; $("ed_company").value=c.company||""; $("ed_position").value=c.position||""; $("ed_addr1").value=c.address_line1||""; $("ed_addr2").value=c.address_line2||""; $("ed_city").value=c.city||""; $("ed_state").value=c.state||""; $("ed_zip").value=c.postal_code||""; $("ed_country").value=c.country||""; $("ed_notes").value=c.notes||""; }
  else { clearEditor(); }
}
function closeEditor(){ $("editor").style.display="none"; clearEditor(); }
async function loadGrid(){
  const q = $("q").value;
  const page = await api.list(q);
  const tb = $("grid").querySelector("tbody"); tb.innerHTML="";
  for(const c of page.data){
    const tr = document.createElement("tr");
    const name = (c.first_name||"")+" "+(c.last_name||"");
    tr.innerHTML = `
      <td>${name}</td><td>${c.company||""}</td><td>${c.city||""}</td><td>${c.state||""}</td>
      <td>${c.email||""}</td><td>${c.phone||""}</td><td>${(typeof c.latitude==="number" && typeof c.longitude==="number") ? "✅" : "—"}</td>
      <td class="actions"><button data-act="edit">Edit</button><button data-act="geo">Geocode</button><button data-act="del">Delete</button></td>`;
    tr.dataset.id = c.id; tr._data = c; tb.appendChild(tr);
  }
}
$("btn-register").onclick = async ()=>{ try{ await api.register($("reg_name").value,$("reg_email").value,$("reg_pass").value); toast("Registered. Now login."); }catch(e){ toast("Register failed: "+e); } };
$("btn-login").onclick = async ()=>{ try{ const t=await api.login($("log_email").value,$("log_pass").value); api.setToken(t.access_token); await refreshMe(); await loadGrid(); }catch(e){ toast("Login failed: "+e); } };
$("btn-logout").onclick = ()=>{ api.setToken(""); location.reload(); };
$("btn-new").onclick = ()=>openEditor(null);
$("btn-cancel").onclick = ()=>closeEditor();
$("btn-save").onclick = async ()=>{
  const c = { first_name:$("ed_first").value, last_name:$("ed_last").value, email:$("ed_email").value, phone:$("ed_phone").value,
    company:$("ed_company").value, position:$("ed_position").value, notes:$("ed_notes").value,
    address_line1:$("ed_addr1").value, address_line2:$("ed_addr2").value, city:$("ed_city").value,
    state:$("ed_state").value, postal_code:$("ed_zip").value, country:$("ed_country").value };
  try{ const id=$("ed_id").value; if(id){ await api.update(id,c); toast("Saved"); } else { await api.create(c); toast("Created"); }
    closeEditor(); await loadGrid(); }catch(e){ toast("Save failed: "+e); }
};
$("btn-refresh").onclick = ()=>loadGrid();
$("btn-search").onclick = ()=>loadGrid();
$("grid").onclick = async (e)=>{
  const btn = e.target.closest("button"); if(!btn) return;
  const tr = e.target.closest("tr"); const id = tr.dataset.id; const c = tr._data;
  if(btn.dataset.act==="edit"){ openEditor(c); }
  if(btn.dataset.act==="geo"){ try{ await api.geocode(id); toast("Geocoded"); await loadGrid(); }catch(err){ toast("Geocode failed: "+err); } }
  if(btn.dataset.act==="del"){ if(confirm("Delete this contact?")){ try{ await api.remove(id); await loadGrid(); }catch(err){ toast("Delete failed: "+err); } } }
};
$("btn-import").onclick = ()=>$("file").click();
$("file").addEventListener("change", async (ev)=>{
  const f = ev.target.files[0]; if(!f) return;
  if(!api.token()){ toast("Please login first."); return; }
  try{
    const preview = await api.importCSV(f, true, true);
    if(!confirm(\`About to import.\\nCreated (preview): \${preview.summary.created}\\nUpdated (preview): \${preview.summary.updated}\\nProceed?\`)) return;
    const result = await api.importCSV(f, true, false);
    toast(\`Import done. Created: \${result.summary.created}, Updated: \${result.summary.updated}, Skipped: \${result.summary.skipped}\`);
    await loadGrid();
  }catch(e){ toast("Import failed: "+e); }
});
(async function init(){ await refreshMe(); if(localStorage.getItem("jwt")){ await loadGrid(); } })();
</script>
</body>
</html>
""")

@app.get("/map", response_class=HTMLResponse)
def map_page(token: str = Query(None)):
    if not GOOGLE_MAPS_API_KEY:
        return HTMLResponse("<h3>Set GOOGLE_MAPS_API_KEY in Render → Environment to use the map.</h3>", status_code=400)
    return HTMLResponse(f"""
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CRM Map</title>
<style>html,body,#map{{height:100%;margin:0}} #top{{position:absolute;z-index:5;background:#fff;padding:8px;border:1px solid #ddd;margin:8px;border-radius:6px}}</style>
</head><body>
<div id="top">Search: <input id="q" placeholder="name/company/city/state"/> <button id="go">Go</button> <span id="status"></span></div>
<div id="map"></div>
<script>
const jwtParam = {("`"+(token or "")+"`")};
function getToken(){ return jwtParam || localStorage.getItem("jwt") || prompt("Paste your JWT token (from Login)"); }
let map, markers=[];
function clearMarkers(){ markers.forEach(m=>m.setMap(null)); markers=[]; }
async function fetchContacts(q){
  const token = getToken();
  const url = new URL("/contacts", window.location.origin);
  url.searchParams.set("limit","1000"); if(q) url.searchParams.set("q", q);
  const r = await fetch(url, {{ headers: {{ "Authorization":"Bearer "+token }} }});
  if(!r.ok) throw new Error("Failed to load contacts"); return r.json();
}
function title(c){ return ((c.first_name||"")+" "+(c.last_name||"")).trim() + (c.company?(" @ "+c.company):""); }
async function place(q){
  clearMarkers();
  const data = await fetchContacts(q);
  const items = data.data||[];
  const bounds = new google.maps.LatLngBounds();
  let missing=0;
  for(const c of items){
    if(typeof c.latitude!=="number"||typeof c.longitude!=="number"){ missing++; continue; }
    const pos={{lat:c.latitude,lng:c.longitude}};
    const marker=new google.maps.Marker({{position:pos,map,title:title(c)}});
    const info=new google.maps.InfoWindow({{content:`<div><strong>${{title(c)}}</strong><br>${{c.email||""}}<br>${{[c.address_line1,c.city,c.state,c.postal_code,c.country].filter(Boolean).join(", ")}}</div>`}});
    marker.addListener("click",()=>info.open({{anchor:marker,map}}));
    markers.push(marker); bounds.extend(pos);
  }
  if(!bounds.isEmpty()) map.fitBounds(bounds);
  document.getElementById("status").textContent = missing?`(Missing coords: ${missing})`:"";
}
window.initMap=function(){ map=new google.maps.Map(document.getElementById("map"),{{center:{lat:39.5,lng:-98.35},zoom:4}}); place(); document.getElementById("go").onclick=()=>place(document.getElementById("q").value); };
</script>
<script async defer src="https://maps.googleapis.com/maps/api/js?key={GOOGLE_MAPS_API_KEY}&callback=initMap"></script>
</body></html>
""")

# ---------------------------
# Local runner
# ---------------------------

def _open_browser_later(url: str, delay: float = 2.0):
    def _op(): time.sleep(delay); import webbrowser; webbrowser.open(url)
    threading.Thread(target=_op, daemon=True).start()

if __name__ == "__main__":
    import uvicorn
    url = f"http://127.0.0.1:{PORT}/app"
    _open_browser_later(url, 2.0)
    uvicorn.run("main:app", host="0.0.0.0", port=PORT)

    if data.get("status") != "OK" or not data.get("results"):
        raise HTTPException(status_code=404, detail=f"Geocoding failed: {data.get('status')}")
    loc = data["results"][0]["geometry"]["location"]
    return float(loc["lat"]), float(loc["lng"])
