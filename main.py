from __future__ import annotations
import os, csv, io, datetime as dt
from typing import Optional, List
from pathlib import Path

import requests
from fastapi import FastAPI, Depends, HTTPException, Query, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, field_validator, EmailStr
from sqlalchemy import (
    create_engine, String, Integer, Boolean, DateTime, Text, Enum, ForeignKey,
    Float, func, Index, or_
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def _load_env_file() -> None:
    if os.path.exists('.env'):
        with open('.env', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                os.environ.setdefault(k.strip(), v.strip())

_load_env_file()

JWT_SECRET = os.getenv('JWT_SECRET', 'change-this-in-production')
JWT_ALG = 'HS256'
JWT_EXPIRE_MIN = int(os.getenv('JWT_EXPIRE_MIN', '1440'))
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./crm.db')
GOOGLE_MAPS_API_KEY = os.getenv('GOOGLE_MAPS_API_KEY', '')
PORT = int(os.getenv('PORT', '10000'))

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass

engine = create_engine(
    DATABASE_URL,
    connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {}
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/login')


def hash_password(p: str) -> str:
    return pwd_context.hash(p)


def verify_password(p: str, h: str) -> bool:
    return pwd_context.verify(p, h)


def create_access_token(subj: str, minutes: int = JWT_EXPIRE_MIN) -> str:
    now = dt.datetime.utcnow()
    exp = now + dt.timedelta(minutes=minutes)
    return jwt.encode(
        {'sub': subj, 'iat': int(now.timestamp()), 'exp': int(exp.timestamp())},
        JWT_SECRET, algorithm=JWT_ALG,
    )


def decode_token(t: str) -> str:
    try:
        payload = jwt.decode(t, JWT_SECRET, algorithms=[JWT_ALG])
        sub = payload.get('sub')
        if not sub:
            raise JWTError('Missing sub')
        return str(sub)
    except JWTError as e:
        raise HTTPException(401, 'Invalid or expired token') from e

# ---------------------------------------------------------------------------
# ORM Models
# ---------------------------------------------------------------------------
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


Index('ix_contacts_name', Contact.first_name, Contact.last_name)
Index('ix_contacts_company_email', Contact.company, Contact.email)

InteractionKind = Enum('call', 'email', 'meeting', 'note', name='interaction_kind')


class InventoryItem(Base):
    __tablename__ = 'inventory_items'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), index=True)
    zone: Mapped[Optional[str]] = mapped_column(String(40), index=True)
    brand: Mapped[str] = mapped_column(String(120), index=True)
    model: Mapped[Optional[str]] = mapped_column(String(120))
    size: Mapped[str] = mapped_column(String(80), index=True)
    position: Mapped[Optional[str]] = mapped_column(String(40))
    condition: Mapped[str] = mapped_column(String(40), default='New')
    quantity: Mapped[int] = mapped_column(Integer, default=0)
    unit_cost: Mapped[float] = mapped_column(Float, default=0.0)
    low_stock_threshold: Mapped[int] = mapped_column(Integer, default=5)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class Interaction(Base):
    __tablename__ = 'interactions'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    contact_id: Mapped[int] = mapped_column(ForeignKey('contacts.id', ondelete='CASCADE'), index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), index=True)
    kind: Mapped[str] = mapped_column(InteractionKind)
    summary: Mapped[str] = mapped_column(Text)
    occurred_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=func.now(), index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------
class Token(BaseModel):
    access_token: str
    token_type: str = 'bearer'


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str

    @field_validator('password')
    @classmethod
    def strong(cls, v):
        if len(v) < 6:
            raise ValueError('password too short')
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


class InventoryItemCreate(BaseModel):
    zone: Optional[str] = None
    brand: str
    model: Optional[str] = None
    size: str
    position: Optional[str] = None
    condition: str = 'New'
    quantity: int = 0
    unit_cost: float = 0.0
    low_stock_threshold: int = 5


class InventoryItemUpdate(BaseModel):
    zone: Optional[str] = None
    brand: Optional[str] = None
    model: Optional[str] = None
    size: Optional[str] = None
    position: Optional[str] = None
    condition: Optional[str] = None
    quantity: Optional[int] = None
    unit_cost: Optional[float] = None
    low_stock_threshold: Optional[int] = None


class InventoryItemOut(BaseModel):
    id: int
    zone: Optional[str] = None
    brand: str
    model: Optional[str] = None
    size: str
    position: Optional[str] = None
    condition: str
    quantity: int
    unit_cost: float
    ext_value: float
    low_stock_threshold: int
    created_at: dt.datetime
    updated_at: dt.datetime

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title='Mini CRM Backend', version='1.0')
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

# Mount static files
STATIC_DIR = Path(__file__).resolve().parent / 'static'
STATIC_DIR.mkdir(exist_ok=True)
app.mount('/static', StaticFiles(directory=str(STATIC_DIR), html=True), name='static')


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
        raise HTTPException(status_code=401, detail='User not found')
    return user

# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
@app.on_event('startup')
def startup():
    Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------------------------
# Routes – Health
# ---------------------------------------------------------------------------
@app.get('/')
def root():
    return {'ok': True, 'msg': 'Mini CRM backend running.'}

# ---------------------------------------------------------------------------
# Routes – Auth
# ---------------------------------------------------------------------------
@app.post('/auth/register', response_model=UserOut)
def register(body: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(400, 'Email already registered')
    user = User(email=body.email, full_name=body.full_name, hashed_password=hash_password(body.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post('/auth/login', response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(400, 'Invalid credentials')
    return Token(access_token=create_access_token(user.email))


@app.get('/auth/me', response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user

# ---------------------------------------------------------------------------
# Routes – Contacts
# ---------------------------------------------------------------------------
@app.post('/contacts', response_model=ContactOut)
def create_contact(body: ContactCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    data = body.model_dump(exclude_unset=True)
    # Geocode address if Google Maps key is available
    if GOOGLE_MAPS_API_KEY and any(data.get(f) for f in ('address_line1', 'city', 'state', 'postal_code', 'country')):
        parts = [data.get(f, '') for f in ('address_line1', 'city', 'state', 'postal_code', 'country')]
        addr = ', '.join(p for p in parts if p)
        try:
            resp = requests.get(
                'https://maps.googleapis.com/maps/api/geocode/json',
                params={'address': addr, 'key': GOOGLE_MAPS_API_KEY}, timeout=5,
            )
            results = resp.json().get('results', [])
            if results:
                loc = results[0]['geometry']['location']
                data['latitude'] = loc['lat']
                data['longitude'] = loc['lng']
        except Exception:
            pass
    contact = Contact(owner_id=user.id, **data)
    db.add(contact)
    db.commit()
    db.refresh(contact)
    return contact


@app.get('/contacts', response_model=List[ContactOut])
def list_contacts(
    q: Optional[str] = Query(None, description='Search across name, email, phone, company'),
    sort: str = Query('created_at', description='Sort field'),
    order: str = Query('desc', description='asc or desc'),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(Contact).filter(Contact.owner_id == user.id)
    if q:
        like = f'%{q}%'
        query = query.filter(or_(
            Contact.first_name.ilike(like), Contact.last_name.ilike(like),
            Contact.email.ilike(like), Contact.phone.ilike(like),
            Contact.company.ilike(like),
        ))
    col = getattr(Contact, sort, Contact.created_at)
    query = query.order_by(col.desc() if order == 'desc' else col.asc())
    return query.offset(offset).limit(limit).all()


@app.get('/contacts/{contact_id}', response_model=ContactOut)
def get_contact(contact_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    contact = db.query(Contact).filter(Contact.id == contact_id, Contact.owner_id == user.id).first()
    if not contact:
        raise HTTPException(404, 'Contact not found')
    return contact


@app.patch('/contacts/{contact_id}', response_model=ContactOut)
def update_contact(contact_id: int, body: ContactUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    contact = db.query(Contact).filter(Contact.id == contact_id, Contact.owner_id == user.id).first()
    if not contact:
        raise HTTPException(404, 'Contact not found')
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(contact, k, v)
    db.commit()
    db.refresh(contact)
    return contact


@app.delete('/contacts/{contact_id}')
def delete_contact(contact_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    contact = db.query(Contact).filter(Contact.id == contact_id, Contact.owner_id == user.id).first()
    if not contact:
        raise HTTPException(404, 'Contact not found')
    db.delete(contact)
    db.commit()
    return {'ok': True}


@app.get('/contacts/export/csv')
def export_csv(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    contacts = db.query(Contact).filter(Contact.owner_id == user.id).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['first_name', 'last_name', 'email', 'phone', 'company', 'position', 'city', 'state', 'country'])
    for c in contacts:
        writer.writerow([c.first_name, c.last_name, c.email, c.phone, c.company, c.position, c.city, c.state, c.country])
    buf.seek(0)
    return StreamingResponse(buf, media_type='text/csv', headers={'Content-Disposition': 'attachment; filename=contacts.csv'})


@app.post('/contacts/import/csv')
def import_csv(file: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    content = file.file.read().decode('utf-8')
    reader = csv.DictReader(io.StringIO(content))
    count = 0
    for row in reader:
        contact = Contact(
            owner_id=user.id,
            first_name=row.get('first_name', ''),
            last_name=row.get('last_name', ''),
            email=row.get('email') or None,
            phone=row.get('phone') or None,
            company=row.get('company') or None,
            position=row.get('position') or None,
            city=row.get('city') or None,
            state=row.get('state') or None,
            country=row.get('country') or None,
        )
        db.add(contact)
        count += 1
    db.commit()
    return {'ok': True, 'imported': count}

# ---------------------------------------------------------------------------
# Routes – Interactions
# ---------------------------------------------------------------------------
@app.post('/contacts/{contact_id}/interactions', response_model=InteractionOut)
def create_interaction(contact_id: int, body: InteractionCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    contact = db.query(Contact).filter(Contact.id == contact_id, Contact.owner_id == user.id).first()
    if not contact:
        raise HTTPException(404, 'Contact not found')
    interaction = Interaction(
        contact_id=contact_id, owner_id=user.id,
        kind=body.kind, summary=body.summary,
        occurred_at=body.occurred_at or dt.datetime.utcnow(),
    )
    db.add(interaction)
    contact.last_contacted_at = interaction.occurred_at
    db.commit()
    db.refresh(interaction)
    return interaction


@app.get('/contacts/{contact_id}/interactions', response_model=List[InteractionOut])
def list_interactions(contact_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    contact = db.query(Contact).filter(Contact.id == contact_id, Contact.owner_id == user.id).first()
    if not contact:
        raise HTTPException(404, 'Contact not found')
    return db.query(Interaction).filter(Interaction.contact_id == contact_id).order_by(Interaction.occurred_at.desc()).all()

# ---------------------------------------------------------------------------
# Routes – Inventory
# ---------------------------------------------------------------------------
def to_inventory_out(item: InventoryItem) -> InventoryItemOut:
    return InventoryItemOut(
        id=item.id, zone=item.zone, brand=item.brand, model=item.model,
        size=item.size, position=item.position, condition=item.condition,
        quantity=item.quantity, unit_cost=item.unit_cost,
        ext_value=round(item.quantity * item.unit_cost, 2),
        low_stock_threshold=item.low_stock_threshold,
        created_at=item.created_at, updated_at=item.updated_at,
    )


@app.get('/inventory', response_model=List[InventoryItemOut])
def list_inventory(
    q: Optional[str] = Query(None),
    zone: Optional[str] = Query(None),
    brand: Optional[str] = Query(None),
    stock_filter: Optional[str] = Query(None, description='all, low_stock, out_of_stock'),
    sort: str = Query('brand'),
    order: str = Query('asc'),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(InventoryItem).filter(InventoryItem.owner_id == user.id)
    if q:
        like = f'%{q}%'
        query = query.filter(or_(
            InventoryItem.brand.ilike(like), InventoryItem.model.ilike(like),
            InventoryItem.size.ilike(like), InventoryItem.zone.ilike(like),
        ))
    if zone:
        query = query.filter(InventoryItem.zone == zone)
    if brand:
        query = query.filter(InventoryItem.brand == brand)
    if stock_filter == 'low_stock':
        query = query.filter(InventoryItem.quantity > 0, InventoryItem.quantity <= InventoryItem.low_stock_threshold)
    elif stock_filter == 'out_of_stock':
        query = query.filter(InventoryItem.quantity == 0)
    col = getattr(InventoryItem, sort, InventoryItem.brand)
    query = query.order_by(col.desc() if order == 'desc' else col.asc())
    items = query.offset(offset).limit(limit).all()
    return [to_inventory_out(i) for i in items]


@app.get('/inventory/summary')
def inventory_summary(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    items = db.query(InventoryItem).filter(InventoryItem.owner_id == user.id).all()
    total_items = len(items)
    total_qty = sum(i.quantity for i in items)
    total_value = sum(i.quantity * i.unit_cost for i in items)
    low_stock = sum(1 for i in items if 0 < i.quantity <= i.low_stock_threshold)
    out_of_stock = sum(1 for i in items if i.quantity == 0)
    return {
        'total_items': total_items, 'total_quantity': total_qty,
        'total_value': round(total_value, 2), 'low_stock': low_stock,
        'out_of_stock': out_of_stock,
    }


@app.post('/inventory', response_model=InventoryItemOut)
def create_inventory_item(body: InventoryItemCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    item = InventoryItem(owner_id=user.id, **body.model_dump())
    db.add(item)
    db.commit()
    db.refresh(item)
    return to_inventory_out(item)


@app.patch('/inventory/{item_id}', response_model=InventoryItemOut)
def update_inventory_item(item_id: int, body: InventoryItemUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    item = db.query(InventoryItem).filter(InventoryItem.id == item_id, InventoryItem.owner_id == user.id).first()
    if not item:
        raise HTTPException(404, 'Inventory item not found')
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(item, k, v)
    db.commit()
    db.refresh(item)
    return to_inventory_out(item)


@app.delete('/inventory/{item_id}')
def delete_inventory_item(item_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    item = db.query(InventoryItem).filter(InventoryItem.id == item_id, InventoryItem.owner_id == user.id).first()
    if not item:
        raise HTTPException(404, 'Inventory item not found')
    db.delete(item)
    db.commit()
    return {'ok': True}


@app.post('/inventory/seed')
def seed_inventory(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Seed inventory with Oxley Tire physical count data (March 2026)."""
    existing = db.query(InventoryItem).filter(InventoryItem.owner_id == user.id).count()
    if existing > 0:
        return {'ok': False, 'msg': 'Inventory already has items', 'count': existing}
    seed_data = [
        ('#13A', 'Royal Black', 'DL301', '11R22.5', 'CSD', 'New', 4, 220),
        ('#13A', 'Amulet', 'AT505', '11R22.5', 'AP', 'New', 52, 238),
        ('#13A', 'Amulet', 'AD507', '11R22.5', 'CSD', 'New', 24, 249),
        ('#13A', 'Royal Black', 'SL101', '11R24.5', 'AP', 'New', 3, 235),
        ('#13A', 'Amulet', 'AT505', '11R24.5', 'AP', 'New', 23, 247),
        ('#13A', 'Amulet', 'AD507', '11R24.5', 'CSD', 'New', 23, 273),
        ('#13A', 'Trans Eagle', None, '205/75R15', 'AP', 'New', 2, 100),
        ('#13A', 'Advance', None, '225/75R15', 'AP', 'New', 3, 140),
        ('#13A', 'Trans Eagle', None, '225/90R16', 'AP', 'New', 1, 125),
        ('#13A', 'Amulet', 'AT505', '235/75R17.5', 'AP', 'New', 11, 133),
        ('#13A', 'Advance', None, '235/85R16', 'AP', 'New', 1, 140),
        ('#13A', 'Synergy', 'SP500', '235/85R16', 'AP', 'New', 2, 120),
        ('#13A', 'Amulet', 'AT505', '255/70R22.5', 'AP', 'New', 62, 167),
        ('#13A', 'Lanvigator', 'SL101', '295/75R22.5', 'AP', 'New', 1, 215),
        ('#13A', 'Amulet', 'AD507', '295/75R22.5', 'CSD', 'New', 8, 237),
        ('#13A', 'Amulet', 'AA612', '385/65R22.5', 'AP', 'New', 2, 373),
        ('#13A', 'Amulet', 'AA612', '425/65R22.5', 'AP', 'New', 8, 443),
        ('#13A', 'Toyo', 'M149', '425/65R22.5', 'AP', 'New', 2, 665),
        ('#13A', 'SU', '720', '445/65R22.5', 'AP', 'New', 1, 375),
        ('#13A', 'Amulet', 'AT505', 'ST235/80R16', 'AP', 'New', 11, 115),
        ('#13A', 'Amulet', 'AT505', 'ST235/85R16', 'AP', 'New', 1, 123),
        ('#7', 'Royal Black', 'TL001', '11R22.5', 'AP', 'New', 1, 195),
        ('#7', 'Royal Black', 'DL301', '11R22.5', 'CSD', 'New', 10, 220),
        ('#7', 'Amulet', 'AD507', '11R22.5', 'CSD', 'New', 10, 238),
        ('#7', 'Synergy', 'DP209', '11R22.5', 'CSD', 'New', 8, 225),
        ('#7', 'Gold Trip', None, '11R22.5', 'AP', 'New', 1, 220),
        ('#7', 'APlus', 'AV211', '11R22.5', 'AP', 'New', 2, 350),
        ('#7', 'Conti', 'CH52', '11R22.5', 'AP', 'New', 2, 210),
        ('#7', 'Amulet', 'Hwy Cap', '11R22.5', 'AP', 'New', 3, 215),
        ('#7', 'Royal Black', 'SL101', '11R24.5', 'AP', 'New', 4, 235),
        ('#7', 'Royal Black', 'AM201', '11R24.5', 'AP', 'New', 4, 240),
        ('#7', 'Amulet', 'AD507', '11R24.5', 'CSD', 'New', 16, 261),
        ('#7', 'Amulet', 'AT505', '11R24.5', 'AP', 'New', 2, 247),
        ('#7', 'Synergy', 'DP209', '11R24.5', 'CSD', 'New', 4, 240),
        ('#7', 'Lexmont', None, '11R24.5', 'CSD', 'New', 1, 240),
        ('#7', 'Hill Rock', 'HRD1', '11R24.5', 'CSD', 'New', 2, 215),
        ('#7', 'Good Trip', None, '215/75R17.5', 'AP', 'New', 2, 230),
        ('#7', 'Royal Black', 'AT', '235/80R17', 'AP', 'New', 2, 100),
        ('#7', 'Royal Black', 'SL101', '255/70R22.5', 'AP', 'New', 3, 165),
        ('#7', 'Royal Black', 'AM201', '255/70R22.5', 'Plus', 'New', 2, 165),
        ('#7', 'Land Golden', None, '255/70R22.5', 'AP', 'New', 4, 160),
        ('#7', 'Royal Black', 'TL001', '295/75R22.5', 'AP', 'New', 3, 190),
        ('#7', 'Amulet', 'AD507', '295/75R22.5', 'CSD', 'New', 5, 237),
        ('#7', 'Amulet', 'AD170', '295/75R22.5', 'AP', 'New', 10, 265),
        ('#7', 'NAMA', None, '295/75R22.5', 'CSD', 'New', 6, 208),
        ('#7', 'Royal Black', 'SL101', '315/80R22.5', 'AP', 'New', 2, 260),
        ('#7', 'Royal Black', 'SL102', '315/80R22.5', 'AP', 'New', 12, 285),
        ('#7', 'Royal Black', 'AV211', '315/80R22.5', 'AP', 'New', 4, 295),
        ('#7', 'Amulet', 'AT505', '315/80R22.5', 'AP', 'New', 2, 317),
        ('#7', 'Lancaster', None, '315/80R22.5', 'AP', 'New', 1, 260),
        ('#7', 'Amulet', 'AA612', '385/65R22.5', 'AP', 'New', 1, 373),
        ('#7', 'Lancaster', None, '385/65R22.5', 'AP', 'New', 2, 295),
        ('#7', 'Atlas', None, '425/65R22.5', 'AP', 'New', 1, 350),
        ('#7', 'Atlas', 'APW-095', '425/65R22.5', 'AP', 'New', 2, 350),
        ('#7', 'Amulet', 'AT505', 'ST235/80R16', 'AP', 'New', 1, 115),
        ('#7', 'Amulet', 'AT505', 'ST235/85R16', 'AP', 'New', 4, 123),
    ]
    for zone, brand, model, size, position, condition, qty, cost in seed_data:
        item = InventoryItem(
            owner_id=user.id, zone=zone, brand=brand, model=model,
            size=size, position=position, condition=condition,
            quantity=qty, unit_cost=cost,
        )
        db.add(item)
    db.commit()
    return {'ok': True, 'seeded': len(seed_data)}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    import uvicorn
    uvicorn.run('main:app', host='0.0.0.0', port=PORT, reload=True)
