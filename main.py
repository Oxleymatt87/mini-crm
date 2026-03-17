"""Mini CRM Backend - Full Featured API"""
from __future__ import annotations
import os
import csv
import io
import datetime as dt
import secrets
import threading
import time
from typing import Optional, List
from urllib.parse import urlencode

import requests
from fastapi import FastAPI, Depends, HTTPException, Query, UploadFile, File
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from jwt.exceptions import InvalidTokenError as JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, field_validator, EmailStr
from sqlalchemy import (
    create_engine, String, Integer, Boolean, DateTime, Text, Enum, ForeignKey,
    Float, func, Index, or_
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session


def _load_env_file() -> None:
    """Load environment variables from .env file if it exists."""
    if os.path.exists('.env'):
        with open('.env', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                os.environ.setdefault(k.strip(), v.strip())


_load_env_file()

# Configuration
JWT_SECRET = os.getenv('JWT_SECRET', 'change-this-in-production')
JWT_ALG = 'HS256'
JWT_EXPIRE_MIN = int(os.getenv('JWT_EXPIRE_MIN', '1440'))
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./crm.db')
GOOGLE_MAPS_API_KEY = os.getenv('GOOGLE_MAPS_API_KEY', '')
PORT = int(os.getenv('PORT', '10000'))

# QuickBooks OAuth Configuration
QB_CLIENT_ID = os.getenv('QB_CLIENT_ID', '')
QB_CLIENT_SECRET = os.getenv('QB_CLIENT_SECRET', '')
QB_REDIRECT_URI = os.getenv('QB_REDIRECT_URI', 'http://localhost:10000/quickbooks/callback')
QB_ENVIRONMENT = os.getenv('QB_ENVIRONMENT', 'sandbox')  # 'sandbox' or 'production'
QB_AUTH_URL = 'https://appcenter.intuit.com/connect/oauth2'
QB_TOKEN_URL = 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer'
QB_API_BASE = 'https://sandbox-quickbooks.api.intuit.com' if QB_ENVIRONMENT == 'sandbox' else 'https://quickbooks.api.intuit.com'

# Database setup
class Base(DeclarativeBase):
    pass


engine = create_engine(
    DATABASE_URL,
    connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {}
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Auth setup
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/login')


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_access_token(subject: str, minutes: int = JWT_EXPIRE_MIN) -> str:
    now = dt.datetime.utcnow()
    exp = now + dt.timedelta(minutes=minutes)
    return jwt.encode(
        {'sub': subject, 'iat': int(now.timestamp()), 'exp': int(exp.timestamp())},
        JWT_SECRET,
        algorithm=JWT_ALG
    )


def decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        sub = payload.get('sub')
        if not sub:
            raise JWTError('Missing sub')
        return str(sub)
    except JWTError as e:
        raise HTTPException(401, 'Invalid or expired token') from e


# Models
class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(255))
    hashed_password: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    contacts: Mapped[List['Contact']] = relationship(back_populates='owner', cascade='all, delete-orphan')


class Contact(Base):
    __tablename__ = 'contacts'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), index=True)
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
    owner: Mapped[User] = relationship(back_populates='contacts')
    interactions: Mapped[List['Interaction']] = relationship(back_populates='contact', cascade='all, delete-orphan')


Index('ix_contacts_name', Contact.first_name, Contact.last_name)
Index('ix_contacts_company_email', Contact.company, Contact.email)


class QuickBooksToken(Base):
    """Store QuickBooks OAuth tokens per user."""
    __tablename__ = 'quickbooks_tokens'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), unique=True, index=True)
    realm_id: Mapped[str] = mapped_column(String(50))  # QuickBooks company ID
    access_token: Mapped[str] = mapped_column(Text)
    refresh_token: Mapped[str] = mapped_column(Text)
    access_token_expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    refresh_token_expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


# Store OAuth state tokens temporarily (in production, use Redis or similar)
_oauth_states: dict[str, int] = {}

InteractionKind = Enum('call', 'email', 'meeting', 'note', name='interaction_kind')


class Interaction(Base):
    __tablename__ = 'interactions'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    contact_id: Mapped[int] = mapped_column(ForeignKey('contacts.id', ondelete='CASCADE'), index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), index=True)
    kind: Mapped[str] = mapped_column(InteractionKind)
    summary: Mapped[str] = mapped_column(Text)
    occurred_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=func.now(), index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    contact: Mapped[Contact] = relationship(back_populates='interactions')


# Schemas
class Token(BaseModel):
    access_token: str
    token_type: str = 'bearer'


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str

    @field_validator('password')
    @classmethod
    def strong_password(cls, v):
        if len(v) < 6:
            raise ValueError('password must be at least 6 characters')
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


# App setup
app = FastAPI(title="Mini CRM Backend", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    email = decode_token(token)
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def geocode_address(contact: Contact) -> tuple[Optional[float], Optional[float]]:
    """Geocode a contact's address using Google Maps API."""
    if not GOOGLE_MAPS_API_KEY:
        return None, None

    address_parts = [
        contact.address_line1,
        contact.address_line2,
        contact.city,
        contact.state,
        contact.postal_code,
        contact.country
    ]
    address = ', '.join(p for p in address_parts if p)
    if not address:
        return None, None

    try:
        resp = requests.get(
            'https://maps.googleapis.com/maps/api/geocode/json',
            params={'address': address, 'key': GOOGLE_MAPS_API_KEY},
            timeout=5
        )
        data = resp.json()
        if data.get('status') == 'OK' and data.get('results'):
            loc = data['results'][0]['geometry']['location']
            return loc.get('lat'), loc.get('lng')
    except Exception:
        pass
    return None, None


# Startup
@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)


# Routes - Health
@app.get("/")
def root():
    return {"ok": True, "msg": "Mini CRM backend running."}


@app.get("/health")
def health():
    return {"status": "healthy"}


# Routes - Auth
@app.post("/auth/register", response_model=UserOut)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=hash_password(user_data.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_access_token(user.email)
    return Token(access_token=token)


@app.get("/auth/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user


# Routes - Contacts
@app.post("/contacts", response_model=ContactOut)
def create_contact(
    contact_data: ContactCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    contact = Contact(owner_id=current_user.id, **contact_data.model_dump())
    db.add(contact)
    db.flush()

    # Geocode address if available
    lat, lng = geocode_address(contact)
    if lat is not None:
        contact.latitude = lat
        contact.longitude = lng

    db.commit()
    db.refresh(contact)
    return contact


@app.get("/contacts", response_model=List[ContactOut])
def list_contacts(
    search: Optional[str] = Query(None, description="Search in name, email, company, phone"),
    city: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    company: Optional[str] = Query(None),
    sort_by: str = Query("created_at", description="Sort field"),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Contact).filter(Contact.owner_id == current_user.id)

    # Apply filters
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                Contact.first_name.ilike(search_term),
                Contact.last_name.ilike(search_term),
                Contact.email.ilike(search_term),
                Contact.company.ilike(search_term),
                Contact.phone.ilike(search_term),
            )
        )
    if city:
        query = query.filter(Contact.city.ilike(f"%{city}%"))
    if state:
        query = query.filter(Contact.state.ilike(f"%{state}%"))
    if company:
        query = query.filter(Contact.company.ilike(f"%{company}%"))

    # Apply sorting
    sort_column = getattr(Contact, sort_by, Contact.created_at)
    if sort_order.lower() == "asc":
        query = query.order_by(sort_column.asc())
    else:
        query = query.order_by(sort_column.desc())

    return query.offset(skip).limit(limit).all()


@app.get("/contacts/{contact_id}", response_model=ContactOut)
def get_contact(
    contact_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    contact = db.query(Contact).filter(
        Contact.id == contact_id,
        Contact.owner_id == current_user.id
    ).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    return contact


@app.patch("/contacts/{contact_id}", response_model=ContactOut)
def update_contact(
    contact_id: int,
    contact_data: ContactUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    contact = db.query(Contact).filter(
        Contact.id == contact_id,
        Contact.owner_id == current_user.id
    ).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")

    update_data = contact_data.model_dump(exclude_unset=True)
    address_changed = any(k in update_data for k in ['address_line1', 'address_line2', 'city', 'state', 'postal_code', 'country'])

    for key, value in update_data.items():
        setattr(contact, key, value)

    # Re-geocode if address changed
    if address_changed:
        lat, lng = geocode_address(contact)
        if lat is not None:
            contact.latitude = lat
            contact.longitude = lng

    db.commit()
    db.refresh(contact)
    return contact


@app.delete("/contacts/{contact_id}")
def delete_contact(
    contact_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    contact = db.query(Contact).filter(
        Contact.id == contact_id,
        Contact.owner_id == current_user.id
    ).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    db.delete(contact)
    db.commit()
    return {"ok": True}


# Routes - Interactions
@app.post("/contacts/{contact_id}/interactions", response_model=InteractionOut)
def create_interaction(
    contact_id: int,
    interaction_data: InteractionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    contact = db.query(Contact).filter(
        Contact.id == contact_id,
        Contact.owner_id == current_user.id
    ).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")

    interaction = Interaction(
        contact_id=contact_id,
        owner_id=current_user.id,
        kind=interaction_data.kind,
        summary=interaction_data.summary,
        occurred_at=interaction_data.occurred_at or dt.datetime.utcnow()
    )
    db.add(interaction)

    # Update last_contacted_at on the contact
    contact.last_contacted_at = interaction.occurred_at

    db.commit()
    db.refresh(interaction)
    return interaction


@app.get("/contacts/{contact_id}/interactions", response_model=List[InteractionOut])
def list_interactions(
    contact_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    contact = db.query(Contact).filter(
        Contact.id == contact_id,
        Contact.owner_id == current_user.id
    ).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")

    return db.query(Interaction).filter(
        Interaction.contact_id == contact_id
    ).order_by(Interaction.occurred_at.desc()).offset(skip).limit(limit).all()


@app.delete("/interactions/{interaction_id}")
def delete_interaction(
    interaction_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    interaction = db.query(Interaction).filter(
        Interaction.id == interaction_id,
        Interaction.owner_id == current_user.id
    ).first()
    if not interaction:
        raise HTTPException(status_code=404, detail="Interaction not found")
    db.delete(interaction)
    db.commit()
    return {"ok": True}


# Routes - CSV Import/Export
@app.get("/contacts/export/csv")
def export_contacts_csv(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    contacts = db.query(Contact).filter(Contact.owner_id == current_user.id).all()

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        'first_name', 'last_name', 'email', 'phone', 'company', 'position',
        'address_line1', 'address_line2', 'city', 'state', 'postal_code', 'country', 'notes'
    ])

    # Data
    for c in contacts:
        writer.writerow([
            c.first_name, c.last_name, c.email or '', c.phone or '', c.company or '', c.position or '',
            c.address_line1 or '', c.address_line2 or '', c.city or '', c.state or '',
            c.postal_code or '', c.country or '', c.notes or ''
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=contacts.csv"}
    )


@app.post("/contacts/import/csv")
def import_contacts_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="File must be a CSV")

    content = file.file.read().decode('utf-8')
    reader = csv.DictReader(io.StringIO(content))

    imported = 0
    errors = []

    for i, row in enumerate(reader, start=2):
        try:
            first_name = row.get('first_name', '').strip()
            last_name = row.get('last_name', '').strip()

            if not first_name or not last_name:
                errors.append(f"Row {i}: first_name and last_name are required")
                continue

            contact = Contact(
                owner_id=current_user.id,
                first_name=first_name,
                last_name=last_name,
                email=row.get('email', '').strip() or None,
                phone=row.get('phone', '').strip() or None,
                company=row.get('company', '').strip() or None,
                position=row.get('position', '').strip() or None,
                address_line1=row.get('address_line1', '').strip() or None,
                address_line2=row.get('address_line2', '').strip() or None,
                city=row.get('city', '').strip() or None,
                state=row.get('state', '').strip() or None,
                postal_code=row.get('postal_code', '').strip() or None,
                country=row.get('country', '').strip() or None,
                notes=row.get('notes', '').strip() or None,
            )
            db.add(contact)
            imported += 1
        except Exception as e:
            errors.append(f"Row {i}: {str(e)}")

    db.commit()
    return {"imported": imported, "errors": errors}


# Routes - Dashboard/Stats
@app.get("/stats")
def get_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    total_contacts = db.query(Contact).filter(Contact.owner_id == current_user.id).count()
    total_interactions = db.query(Interaction).filter(Interaction.owner_id == current_user.id).count()

    # Contacts needing follow-up (next_follow_up_at in past or today)
    now = dt.datetime.utcnow()
    follow_ups_due = db.query(Contact).filter(
        Contact.owner_id == current_user.id,
        Contact.next_follow_up_at <= now
    ).count()

    # Recent interactions (last 7 days)
    week_ago = now - dt.timedelta(days=7)
    recent_interactions = db.query(Interaction).filter(
        Interaction.owner_id == current_user.id,
        Interaction.occurred_at >= week_ago
    ).count()

    return {
        "total_contacts": total_contacts,
        "total_interactions": total_interactions,
        "follow_ups_due": follow_ups_due,
        "recent_interactions": recent_interactions
    }


# Routes - QuickBooks Integration
@app.get("/quickbooks/connect")
def quickbooks_connect(current_user: User = Depends(get_current_user)):
    """Initiate QuickBooks OAuth flow."""
    if not QB_CLIENT_ID or not QB_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="QuickBooks not configured. Set QB_CLIENT_ID and QB_CLIENT_SECRET.")

    state = secrets.token_urlsafe(32)
    _oauth_states[state] = current_user.id

    params = {
        'client_id': QB_CLIENT_ID,
        'response_type': 'code',
        'scope': 'com.intuit.quickbooks.accounting',
        'redirect_uri': QB_REDIRECT_URI,
        'state': state,
    }
    auth_url = f"{QB_AUTH_URL}?{urlencode(params)}"
    return {"auth_url": auth_url}


@app.get("/quickbooks/callback")
def quickbooks_callback(
    code: str = Query(...),
    state: str = Query(...),
    realmId: str = Query(...),
    db: Session = Depends(get_db)
):
    """Handle QuickBooks OAuth callback."""
    user_id = _oauth_states.pop(state, None)
    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid or expired state token")

    # Exchange code for tokens
    auth = (QB_CLIENT_ID, QB_CLIENT_SECRET)
    resp = requests.post(
        QB_TOKEN_URL,
        auth=auth,
        headers={'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'},
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': QB_REDIRECT_URI,
        },
        timeout=30
    )

    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {resp.text}")

    tokens = resp.json()
    now = dt.datetime.utcnow()

    # Save or update tokens
    qb_token = db.query(QuickBooksToken).filter(QuickBooksToken.user_id == user_id).first()
    if qb_token:
        qb_token.realm_id = realmId
        qb_token.access_token = tokens['access_token']
        qb_token.refresh_token = tokens['refresh_token']
        qb_token.access_token_expires_at = now + dt.timedelta(seconds=tokens['expires_in'])
        qb_token.refresh_token_expires_at = now + dt.timedelta(seconds=tokens['x_refresh_token_expires_in'])
    else:
        qb_token = QuickBooksToken(
            user_id=user_id,
            realm_id=realmId,
            access_token=tokens['access_token'],
            refresh_token=tokens['refresh_token'],
            access_token_expires_at=now + dt.timedelta(seconds=tokens['expires_in']),
            refresh_token_expires_at=now + dt.timedelta(seconds=tokens['x_refresh_token_expires_in']),
        )
        db.add(qb_token)

    db.commit()
    return RedirectResponse(url="/?quickbooks=connected")


def get_qb_access_token(user_id: int, db: Session) -> tuple[str, str]:
    """Get valid QuickBooks access token, refreshing if needed."""
    qb_token = db.query(QuickBooksToken).filter(QuickBooksToken.user_id == user_id).first()
    if not qb_token:
        raise HTTPException(status_code=400, detail="QuickBooks not connected. Visit /quickbooks/connect first.")

    now = dt.datetime.utcnow()

    # Check if refresh token expired
    if qb_token.refresh_token_expires_at < now:
        db.delete(qb_token)
        db.commit()
        raise HTTPException(status_code=400, detail="QuickBooks authorization expired. Please reconnect.")

    # Refresh access token if expired
    if qb_token.access_token_expires_at < now:
        resp = requests.post(
            QB_TOKEN_URL,
            auth=(QB_CLIENT_ID, QB_CLIENT_SECRET),
            headers={'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'},
            data={'grant_type': 'refresh_token', 'refresh_token': qb_token.refresh_token},
            timeout=30
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to refresh QuickBooks token")

        tokens = resp.json()
        qb_token.access_token = tokens['access_token']
        qb_token.refresh_token = tokens['refresh_token']
        qb_token.access_token_expires_at = now + dt.timedelta(seconds=tokens['expires_in'])
        qb_token.refresh_token_expires_at = now + dt.timedelta(seconds=tokens['x_refresh_token_expires_in'])
        db.commit()

    return qb_token.access_token, qb_token.realm_id


@app.get("/quickbooks/status")
def quickbooks_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Check QuickBooks connection status."""
    qb_token = db.query(QuickBooksToken).filter(QuickBooksToken.user_id == current_user.id).first()
    if not qb_token:
        return {"connected": False}

    now = dt.datetime.utcnow()
    return {
        "connected": True,
        "realm_id": qb_token.realm_id,
        "access_token_valid": qb_token.access_token_expires_at > now,
        "refresh_token_valid": qb_token.refresh_token_expires_at > now,
    }


@app.delete("/quickbooks/disconnect")
def quickbooks_disconnect(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Disconnect QuickBooks integration."""
    qb_token = db.query(QuickBooksToken).filter(QuickBooksToken.user_id == current_user.id).first()
    if qb_token:
        db.delete(qb_token)
        db.commit()
    return {"ok": True}


@app.get("/quickbooks/customers")
def list_quickbooks_customers(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List customers from QuickBooks."""
    access_token, realm_id = get_qb_access_token(current_user.id, db)

    resp = requests.get(
        f"{QB_API_BASE}/v3/company/{realm_id}/query",
        headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        },
        params={'query': 'SELECT * FROM Customer MAXRESULTS 100'},
        timeout=30
    )

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"QuickBooks API error: {resp.text}")

    data = resp.json()
    customers = data.get('QueryResponse', {}).get('Customer', [])
    return {"customers": customers}


@app.post("/quickbooks/sync-contact/{contact_id}")
def sync_contact_to_quickbooks(
    contact_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Sync a CRM contact to QuickBooks as a customer."""
    contact = db.query(Contact).filter(
        Contact.id == contact_id,
        Contact.owner_id == current_user.id
    ).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")

    access_token, realm_id = get_qb_access_token(current_user.id, db)

    customer_data = {
        "DisplayName": f"{contact.first_name} {contact.last_name}",
        "GivenName": contact.first_name,
        "FamilyName": contact.last_name,
        "CompanyName": contact.company,
    }

    if contact.email:
        customer_data["PrimaryEmailAddr"] = {"Address": contact.email}
    if contact.phone:
        customer_data["PrimaryPhone"] = {"FreeFormNumber": contact.phone}
    if contact.address_line1:
        customer_data["BillAddr"] = {
            "Line1": contact.address_line1,
            "Line2": contact.address_line2,
            "City": contact.city,
            "CountrySubDivisionCode": contact.state,
            "PostalCode": contact.postal_code,
            "Country": contact.country,
        }

    resp = requests.post(
        f"{QB_API_BASE}/v3/company/{realm_id}/customer",
        headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
        json=customer_data,
        timeout=30
    )

    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=resp.status_code, detail=f"QuickBooks API error: {resp.text}")

    return {"ok": True, "quickbooks_customer": resp.json().get('Customer')}


@app.post("/quickbooks/import-customers")
def import_quickbooks_customers(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Import QuickBooks customers as CRM contacts."""
    access_token, realm_id = get_qb_access_token(current_user.id, db)

    resp = requests.get(
        f"{QB_API_BASE}/v3/company/{realm_id}/query",
        headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        },
        params={'query': 'SELECT * FROM Customer MAXRESULTS 500'},
        timeout=30
    )

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"QuickBooks API error: {resp.text}")

    data = resp.json()
    customers = data.get('QueryResponse', {}).get('Customer', [])

    imported = 0
    for cust in customers:
        first_name = cust.get('GivenName', cust.get('DisplayName', 'Unknown'))
        last_name = cust.get('FamilyName', '')

        # Skip if contact with same name already exists
        existing = db.query(Contact).filter(
            Contact.owner_id == current_user.id,
            Contact.first_name == first_name,
            Contact.last_name == last_name
        ).first()
        if existing:
            continue

        bill_addr = cust.get('BillAddr', {})
        contact = Contact(
            owner_id=current_user.id,
            first_name=first_name,
            last_name=last_name or first_name,
            email=cust.get('PrimaryEmailAddr', {}).get('Address'),
            phone=cust.get('PrimaryPhone', {}).get('FreeFormNumber'),
            company=cust.get('CompanyName'),
            address_line1=bill_addr.get('Line1'),
            address_line2=bill_addr.get('Line2'),
            city=bill_addr.get('City'),
            state=bill_addr.get('CountrySubDivisionCode'),
            postal_code=bill_addr.get('PostalCode'),
            country=bill_addr.get('Country'),
        )
        db.add(contact)
        imported += 1

    db.commit()
    return {"imported": imported, "total_customers": len(customers)}


class InitTokensRequest(BaseModel):
    access_token: str
    refresh_token: str
    realm_id: str


@app.post("/quickbooks/init-tokens")
def init_quickbooks_tokens(
    token_data: InitTokensRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Initialize QuickBooks connection with existing tokens."""
    now = dt.datetime.utcnow()

    qb_token = db.query(QuickBooksToken).filter(QuickBooksToken.user_id == current_user.id).first()
    if qb_token:
        qb_token.realm_id = token_data.realm_id
        qb_token.access_token = token_data.access_token
        qb_token.refresh_token = token_data.refresh_token
        qb_token.access_token_expires_at = now + dt.timedelta(hours=1)
        qb_token.refresh_token_expires_at = now + dt.timedelta(days=100)
    else:
        qb_token = QuickBooksToken(
            user_id=current_user.id,
            realm_id=token_data.realm_id,
            access_token=token_data.access_token,
            refresh_token=token_data.refresh_token,
            access_token_expires_at=now + dt.timedelta(hours=1),
            refresh_token_expires_at=now + dt.timedelta(days=100),
        )
        db.add(qb_token)

    db.commit()
    return {"ok": True, "message": "QuickBooks tokens initialized"}


# Background sync worker
_sync_stop_event = threading.Event()
_sync_thread: Optional[threading.Thread] = None
_sync_interval_minutes = int(os.getenv('QB_SYNC_INTERVAL_MINUTES', '30'))


def _background_sync_worker():
    """Background worker that syncs QuickBooks data periodically."""
    while not _sync_stop_event.is_set():
        try:
            db = SessionLocal()
            # Get all users with QuickBooks tokens
            tokens = db.query(QuickBooksToken).all()
            for qb_token in tokens:
                try:
                    # Refresh token if needed
                    now = dt.datetime.utcnow()
                    if qb_token.access_token_expires_at < now:
                        resp = requests.post(
                            QB_TOKEN_URL,
                            auth=(QB_CLIENT_ID, QB_CLIENT_SECRET),
                            headers={'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'},
                            data={'grant_type': 'refresh_token', 'refresh_token': qb_token.refresh_token},
                            timeout=30
                        )
                        if resp.status_code == 200:
                            new_tokens = resp.json()
                            qb_token.access_token = new_tokens['access_token']
                            qb_token.refresh_token = new_tokens['refresh_token']
                            qb_token.access_token_expires_at = now + dt.timedelta(seconds=new_tokens['expires_in'])
                            qb_token.refresh_token_expires_at = now + dt.timedelta(seconds=new_tokens['x_refresh_token_expires_in'])
                            db.commit()
                except Exception as e:
                    print(f"Sync error for user {qb_token.user_id}: {e}")
            db.close()
        except Exception as e:
            print(f"Background sync error: {e}")

        # Wait for interval or stop signal
        _sync_stop_event.wait(timeout=_sync_interval_minutes * 60)


@app.post("/quickbooks/sync/start")
def start_background_sync(current_user: User = Depends(get_current_user)):
    """Start background QuickBooks sync worker."""
    global _sync_thread
    if _sync_thread and _sync_thread.is_alive():
        return {"ok": True, "message": "Sync already running"}

    _sync_stop_event.clear()
    _sync_thread = threading.Thread(target=_background_sync_worker, daemon=True)
    _sync_thread.start()
    return {"ok": True, "message": f"Background sync started (interval: {_sync_interval_minutes} minutes)"}


@app.post("/quickbooks/sync/stop")
def stop_background_sync(current_user: User = Depends(get_current_user)):
    """Stop background QuickBooks sync worker."""
    _sync_stop_event.set()
    return {"ok": True, "message": "Background sync stopping"}


@app.get("/quickbooks/sync/status")
def get_sync_status(current_user: User = Depends(get_current_user)):
    """Get background sync status."""
    return {
        "running": _sync_thread is not None and _sync_thread.is_alive(),
        "interval_minutes": _sync_interval_minutes
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
