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
from fastapi import FastAPI, Depends, HTTPException, Query, UploadFile, File, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
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
# Fix Render's postgres:// URL for SQLAlchemy 2.x compatibility
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
GOOGLE_MAPS_API_KEY = os.getenv('GOOGLE_MAPS_API_KEY', '')
PORT = int(os.getenv('PORT', '10000'))

# QuickBooks OAuth Configuration - read dynamically for flexibility
def get_qb_client_id():
    return os.getenv('QB_CLIENT_ID', '')

def get_qb_client_secret():
    return os.getenv('QB_CLIENT_SECRET', '')

def get_qb_environment():
    return os.getenv('QB_ENVIRONMENT', 'sandbox')

def get_qb_api_base():
    env = get_qb_environment()
    return 'https://sandbox-quickbooks.api.intuit.com' if env == 'sandbox' else 'https://quickbooks.api.intuit.com'

QB_AUTH_URL = 'https://appcenter.intuit.com/connect/oauth2'
QB_TOKEN_URL = 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer'

# Pre-seeded tokens (set these to auto-initialize QuickBooks on startup)
def get_qb_refresh_token():
    return os.getenv('QB_REFRESH_TOKEN', '')

def get_qb_realm_id():
    return os.getenv('QB_REALM_ID', '')

# Google OAuth Configuration (for Drive access)
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET', '')
GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:10000/google/callback')
GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_DRIVE_API = 'https://www.googleapis.com/drive/v3'

# Database setup
class Base(DeclarativeBase):
    pass


engine = create_engine(
    DATABASE_URL,
    connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {}
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Auth setup
pwd_context = CryptContext(
    schemes=['bcrypt'],
    deprecated='auto',
    bcrypt__truncate_error=False  # Silently truncate passwords > 72 bytes
)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/login')


def hash_password(password: str) -> str:
    # bcrypt has a 72-byte limit, truncate to be safe
    password_bytes = password.encode('utf-8')[:72].decode('utf-8', errors='ignore')
    return pwd_context.hash(password_bytes)


def verify_password(password: str, hashed: str) -> bool:
    # bcrypt has a 72-byte limit, truncate to match hash_password
    password_bytes = password.encode('utf-8')[:72].decode('utf-8', errors='ignore')
    return pwd_context.verify(password_bytes, hashed)


def create_access_token(subject: str, minutes: int = JWT_EXPIRE_MIN) -> str:
    now = dt.datetime.now(dt.timezone.utc)
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


class GoogleDriveToken(Base):
    """Store Google OAuth tokens per user for Drive access."""
    __tablename__ = 'google_drive_tokens'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), unique=True, index=True)
    access_token: Mapped[str] = mapped_column(Text)
    refresh_token: Mapped[str] = mapped_column(Text)
    access_token_expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


# OAuth state storage - now in database for multi-worker support
class OAuthState(Base):
    """Store OAuth state tokens in database for multi-worker environments."""
    __tablename__ = 'oauth_states'
    state: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer)
    provider: Mapped[str] = mapped_column(String(20))  # 'quickbooks' or 'google'
    redirect_uri: Mapped[Optional[str]] = mapped_column(String(500))
    frontend_url: Mapped[Optional[str]] = mapped_column(String(500))  # Where to redirect after OAuth
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

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


# Inventory Models
class InventoryItem(Base):
    """Inventory item (tire, part, etc.)"""
    __tablename__ = 'inventory_items'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), index=True)
    sku: Mapped[str] = mapped_column(String(100), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[Optional[str]] = mapped_column(Text)
    category: Mapped[Optional[str]] = mapped_column(String(100), index=True)  # tire, wheel, part, service
    brand: Mapped[Optional[str]] = mapped_column(String(100), index=True)
    size: Mapped[Optional[str]] = mapped_column(String(50))  # e.g., 225/65R17
    quantity: Mapped[int] = mapped_column(Integer, default=0)
    reorder_level: Mapped[int] = mapped_column(Integer, default=5)
    cost: Mapped[Optional[float]] = mapped_column(Float)  # what you pay
    price: Mapped[Optional[float]] = mapped_column(Float)  # what you charge
    location: Mapped[Optional[str]] = mapped_column(String(100))  # warehouse/shelf
    qb_item_id: Mapped[Optional[str]] = mapped_column(String(50))  # QuickBooks Item ID
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    transactions: Mapped[List['InventoryTransaction']] = relationship(back_populates='item', cascade='all, delete-orphan')


Index('ix_inventory_owner_sku', InventoryItem.owner_id, InventoryItem.sku, unique=True)


TransactionType = Enum('receive', 'sell', 'adjust', 'transfer', 'return', name='transaction_type')


class InventoryTransaction(Base):
    """Track stock movements."""
    __tablename__ = 'inventory_transactions'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    item_id: Mapped[int] = mapped_column(ForeignKey('inventory_items.id', ondelete='CASCADE'), index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), index=True)
    transaction_type: Mapped[str] = mapped_column(TransactionType)
    quantity: Mapped[int] = mapped_column(Integer)  # positive for in, negative for out
    unit_cost: Mapped[Optional[float]] = mapped_column(Float)
    reference: Mapped[Optional[str]] = mapped_column(String(255))  # PO#, invoice#, etc.
    notes: Mapped[Optional[str]] = mapped_column(Text)
    contact_id: Mapped[Optional[int]] = mapped_column(ForeignKey('contacts.id', ondelete='SET NULL'), index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    item: Mapped[InventoryItem] = relationship(back_populates='transactions')


# Supplier Models
class Supplier(Base):
    """Tire/parts supplier."""
    __tablename__ = 'suppliers'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    code: Mapped[Optional[str]] = mapped_column(String(50))  # short code like BZO, ATD
    contact_name: Mapped[Optional[str]] = mapped_column(String(255))
    phone: Mapped[Optional[str]] = mapped_column(String(50))
    email: Mapped[Optional[str]] = mapped_column(String(255))
    address: Mapped[Optional[str]] = mapped_column(Text)
    city: Mapped[Optional[str]] = mapped_column(String(100))
    website: Mapped[Optional[str]] = mapped_column(String(255))
    portal_url: Mapped[Optional[str]] = mapped_column(String(500))  # dealer portal URL
    portal_username: Mapped[Optional[str]] = mapped_column(String(255))
    portal_password_encrypted: Mapped[Optional[str]] = mapped_column(Text)  # encrypted credentials
    notes: Mapped[Optional[str]] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    orders: Mapped[List['PurchaseOrder']] = relationship(back_populates='supplier', cascade='all, delete-orphan')


Index('ix_supplier_owner_name', Supplier.owner_id, Supplier.name, unique=True)


OrderStatus = Enum('draft', 'submitted', 'confirmed', 'shipped', 'received', 'cancelled', name='order_status')


class PurchaseOrder(Base):
    """Purchase order to supplier."""
    __tablename__ = 'purchase_orders'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), index=True)
    supplier_id: Mapped[int] = mapped_column(ForeignKey('suppliers.id', ondelete='CASCADE'), index=True)
    order_number: Mapped[str] = mapped_column(String(50), index=True)
    status: Mapped[str] = mapped_column(OrderStatus, default='draft')
    subtotal: Mapped[float] = mapped_column(Float, default=0)
    tax: Mapped[float] = mapped_column(Float, default=0)
    shipping: Mapped[float] = mapped_column(Float, default=0)
    total: Mapped[float] = mapped_column(Float, default=0)
    notes: Mapped[Optional[str]] = mapped_column(Text)
    submitted_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))
    expected_delivery: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    supplier: Mapped[Supplier] = relationship(back_populates='orders')
    items: Mapped[List['PurchaseOrderItem']] = relationship(back_populates='order', cascade='all, delete-orphan')


class PurchaseOrderItem(Base):
    """Line item in a purchase order."""
    __tablename__ = 'purchase_order_items'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    order_id: Mapped[int] = mapped_column(ForeignKey('purchase_orders.id', ondelete='CASCADE'), index=True)
    inventory_item_id: Mapped[Optional[int]] = mapped_column(ForeignKey('inventory_items.id', ondelete='SET NULL'))
    sku: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(String(500))
    quantity: Mapped[int] = mapped_column(Integer)
    unit_cost: Mapped[float] = mapped_column(Float)
    total: Mapped[float] = mapped_column(Float)
    received_qty: Mapped[int] = mapped_column(Integer, default=0)
    order: Mapped[PurchaseOrder] = relationship(back_populates='items')


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


# Inventory Schemas
class InventoryItemCreate(BaseModel):
    sku: str
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    brand: Optional[str] = None
    size: Optional[str] = None
    quantity: int = 0
    reorder_level: int = 5
    cost: Optional[float] = None
    price: Optional[float] = None
    location: Optional[str] = None


class InventoryItemUpdate(BaseModel):
    sku: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    brand: Optional[str] = None
    size: Optional[str] = None
    reorder_level: Optional[int] = None
    cost: Optional[float] = None
    price: Optional[float] = None
    location: Optional[str] = None
    is_active: Optional[bool] = None


class InventoryItemOut(BaseModel):
    id: int
    sku: str
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    brand: Optional[str] = None
    size: Optional[str] = None
    quantity: int
    reorder_level: int
    cost: Optional[float] = None
    price: Optional[float] = None
    location: Optional[str] = None
    qb_item_id: Optional[str] = None
    is_active: bool
    created_at: dt.datetime
    updated_at: dt.datetime


class InventoryTransactionCreate(BaseModel):
    transaction_type: str  # receive, sell, adjust, transfer, return
    quantity: int
    unit_cost: Optional[float] = None
    reference: Optional[str] = None
    notes: Optional[str] = None
    contact_id: Optional[int] = None


class InventoryTransactionOut(BaseModel):
    id: int
    item_id: int
    transaction_type: str
    quantity: int
    unit_cost: Optional[float] = None
    reference: Optional[str] = None
    notes: Optional[str] = None
    contact_id: Optional[int] = None
    created_at: dt.datetime


# Supplier Schemas
class SupplierCreate(BaseModel):
    name: str
    code: Optional[str] = None
    contact_name: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    website: Optional[str] = None
    portal_url: Optional[str] = None
    portal_username: Optional[str] = None
    portal_password: Optional[str] = None  # Will be encrypted
    notes: Optional[str] = None


class SupplierUpdate(BaseModel):
    name: Optional[str] = None
    code: Optional[str] = None
    contact_name: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    website: Optional[str] = None
    portal_url: Optional[str] = None
    portal_username: Optional[str] = None
    portal_password: Optional[str] = None
    notes: Optional[str] = None
    is_active: Optional[bool] = None


class SupplierOut(BaseModel):
    id: int
    name: str
    code: Optional[str] = None
    contact_name: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    website: Optional[str] = None
    portal_url: Optional[str] = None
    portal_username: Optional[str] = None
    has_credentials: bool = False  # True if portal credentials are stored
    notes: Optional[str] = None
    is_active: bool
    created_at: dt.datetime


# Purchase Order Schemas
class PurchaseOrderItemCreate(BaseModel):
    inventory_item_id: Optional[int] = None
    sku: str
    description: str
    quantity: int
    unit_cost: float


class PurchaseOrderItemOut(BaseModel):
    id: int
    inventory_item_id: Optional[int] = None
    sku: str
    description: str
    quantity: int
    unit_cost: float
    total: float
    received_qty: int


class PurchaseOrderCreate(BaseModel):
    supplier_id: int
    notes: Optional[str] = None
    items: List[PurchaseOrderItemCreate]


class PurchaseOrderOut(BaseModel):
    id: int
    supplier_id: int
    supplier_name: str
    order_number: str
    status: str
    subtotal: float
    tax: float
    shipping: float
    total: float
    notes: Optional[str] = None
    submitted_at: Optional[dt.datetime] = None
    expected_delivery: Optional[dt.datetime] = None
    received_at: Optional[dt.datetime] = None
    created_at: dt.datetime
    items: List[PurchaseOrderItemOut] = []


# App setup
app = FastAPI(title="Mini CRM Backend", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files (PWA frontend)
_static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.isdir(_static_dir):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")


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
    try:
        # Drop and recreate oauth_states table to ensure schema is current
        # (it's just temporary state for in-flight OAuth, safe to clear)
        OAuthState.__table__.drop(engine, checkfirst=True)
        Base.metadata.create_all(bind=engine)

        # Verify critical tables exist
        from sqlalchemy import inspect
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        print(f"Database tables: {tables}")
        if 'quickbooks_tokens' not in tables:
            print("WARNING: quickbooks_tokens table missing!")
        else:
            print("QuickBooks tokens table verified")
    except Exception as e:
        print(f"Database initialization error: {e}")

    # Auto-seed QuickBooks tokens from env vars
    qb_refresh = get_qb_refresh_token()
    qb_realm = get_qb_realm_id()
    qb_client = get_qb_client_id()
    qb_secret = get_qb_client_secret()
    if qb_refresh and qb_realm and qb_client and qb_secret:
        try:
            db = SessionLocal()
            # Get first user or create a system user
            user = db.query(User).first()
            if not user:
                user = User(
                    email="system@localhost",
                    full_name="System User",
                    hashed_password=hash_password(secrets.token_urlsafe(32)),
                )
                db.add(user)
                db.commit()
                db.refresh(user)
                print("Created system user for QuickBooks")

            # Check if QB token already exists for this user
            qb_token = db.query(QuickBooksToken).filter(QuickBooksToken.user_id == user.id).first()
            if not qb_token:
                # Get fresh access token using refresh token
                resp = requests.post(
                    QB_TOKEN_URL,
                    auth=(qb_client, qb_secret),
                    headers={'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'},
                    data={'grant_type': 'refresh_token', 'refresh_token': qb_refresh},
                    timeout=30
                )
                if resp.status_code == 200:
                    tokens = resp.json()
                    now = dt.datetime.now(dt.timezone.utc)
                    qb_token = QuickBooksToken(
                        user_id=user.id,
                        realm_id=qb_realm,
                        access_token=tokens['access_token'],
                        refresh_token=tokens['refresh_token'],
                        access_token_expires_at=now + dt.timedelta(seconds=tokens['expires_in']),
                        refresh_token_expires_at=now + dt.timedelta(seconds=tokens['x_refresh_token_expires_in']),
                    )
                    db.add(qb_token)
                    db.commit()
                    print(f"QuickBooks tokens seeded for user {user.id}")
                else:
                    print(f"Failed to get QB access token: {resp.status_code} - {resp.text}")
            else:
                print(f"QuickBooks already configured for user {user.id}")
            db.close()
        except Exception as e:
            print(f"QuickBooks auto-seed error: {e}")


# Routes - Health
@app.get("/")
def root():
    if os.path.isdir(_static_dir):
        return RedirectResponse(url="/static/index.html")
    return {"ok": True, "msg": "Mini CRM backend running."}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/debug/env")
def debug_env():
    """Debug endpoint to check QuickBooks env vars (shows masked values)."""
    client_id = get_qb_client_id()
    client_secret = get_qb_client_secret()
    refresh_token = get_qb_refresh_token()
    realm_id = get_qb_realm_id()

    # Find ALL env vars containing 'qb' or 'quickbooks' (case insensitive)
    all_qb_vars = {k: "SET" for k in os.environ.keys() if 'qb' in k.lower() or 'quickbooks' in k.lower()}

    return {
        "expected_vars": {
            "QB_CLIENT_ID": f"{client_id[:4]}...{client_id[-4:]}" if len(client_id) > 8 else ("SET" if client_id else "NOT SET"),
            "QB_CLIENT_SECRET": "SET" if client_secret else "NOT SET",
            "QB_ENVIRONMENT": get_qb_environment(),
            "QB_REFRESH_TOKEN": "SET" if refresh_token else "NOT SET",
            "QB_REALM_ID": realm_id if realm_id else "NOT SET",
        },
        "actual_env_vars_found": all_qb_vars
    }


# Routes - Auth
@app.post("/auth/register", response_model=UserOut)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    try:
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
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


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
        occurred_at=interaction_data.occurred_at or dt.datetime.now(dt.timezone.utc)
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
    now = dt.datetime.now(dt.timezone.utc)
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
def quickbooks_connect(
    request: Request,
    return_url: str = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Initiate QuickBooks OAuth flow."""
    print(f"[QB Connect] Starting OAuth for user_id={current_user.id}")
    client_id = get_qb_client_id()
    client_secret = get_qb_client_secret()
    if not client_id or not client_secret:
        raise HTTPException(status_code=500, detail="QuickBooks not configured. Set QB_CLIENT_ID and QB_CLIENT_SECRET.")

    # Use environment variable for redirect URI (handles proxy/HTTPS correctly)
    redirect_uri = os.getenv('QB_REDIRECT_URI', str(request.base_url).rstrip('/') + "/quickbooks/callback")

    # Where to redirect after OAuth: explicit param > env var > referer > default
    frontend_url = return_url or os.getenv('FRONTEND_URL') or str(request.base_url).rstrip('/') + "/static/index.html"

    state = secrets.token_urlsafe(32)

    # Store state in database (works across multiple workers/restarts)
    db.query(OAuthState).filter(OAuthState.provider == 'quickbooks', OAuthState.user_id == current_user.id).delete()
    oauth_state = OAuthState(state=state, user_id=current_user.id, provider='quickbooks', redirect_uri=redirect_uri, frontend_url=frontend_url)
    db.add(oauth_state)
    db.commit()

    params = {
        'client_id': client_id,
        'response_type': 'code',
        'scope': 'com.intuit.quickbooks.accounting',
        'redirect_uri': redirect_uri,
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
    print(f"[QB Callback] Received state={state[:20]}..., realmId={realmId}")

    # Retrieve state from database
    oauth_state = db.query(OAuthState).filter(OAuthState.state == state, OAuthState.provider == 'quickbooks').first()
    if not oauth_state:
        print(f"[QB Callback] ERROR: State not found in database")
        raise HTTPException(status_code=400, detail="Invalid or expired state token")

    user_id = oauth_state.user_id
    redirect_uri = oauth_state.redirect_uri
    frontend_url = oauth_state.frontend_url or "/static/index.html"
    print(f"[QB Callback] Found state for user_id={user_id}, frontend_url={frontend_url}")

    # Delete used state
    db.delete(oauth_state)
    db.commit()

    # Exchange code for tokens
    auth = (get_qb_client_id(), get_qb_client_secret())
    resp = requests.post(
        QB_TOKEN_URL,
        auth=auth,
        headers={'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'},
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
        },
        timeout=30
    )

    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {resp.text}")

    tokens = resp.json()
    now = dt.datetime.now(dt.timezone.utc)

    # Save or update tokens with explicit error handling
    try:
        qb_token = db.query(QuickBooksToken).filter(QuickBooksToken.user_id == user_id).first()
        if qb_token:
            print(f"[QB Callback] Updating existing token for user_id={user_id}")
            qb_token.realm_id = realmId
            qb_token.access_token = tokens['access_token']
            qb_token.refresh_token = tokens['refresh_token']
            qb_token.access_token_expires_at = now + dt.timedelta(seconds=tokens['expires_in'])
            qb_token.refresh_token_expires_at = now + dt.timedelta(seconds=tokens['x_refresh_token_expires_in'])
        else:
            print(f"[QB Callback] Creating new token for user_id={user_id}")
            qb_token = QuickBooksToken(
                user_id=user_id,
                realm_id=realmId,
                access_token=tokens['access_token'],
                refresh_token=tokens['refresh_token'],
                access_token_expires_at=now + dt.timedelta(seconds=tokens['expires_in']),
                refresh_token_expires_at=now + dt.timedelta(seconds=tokens['x_refresh_token_expires_in']),
            )
            db.add(qb_token)

        db.flush()  # Force write to DB before commit
        db.commit()

        # Verify the save worked
        verify = db.query(QuickBooksToken).filter(QuickBooksToken.user_id == user_id).first()
        if verify:
            print(f"[QB Callback] SUCCESS: Verified token saved for user_id={user_id}, realm_id={verify.realm_id}")
        else:
            print(f"[QB Callback] ERROR: Token verification failed - not found after commit!")
    except Exception as e:
        print(f"[QB Callback] ERROR saving token: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to save QuickBooks token: {str(e)}")

    # Redirect back to frontend (preserves user's login session)
    # Ensure frontend_url is absolute
    if not frontend_url.startswith('http'):
        base = os.getenv('FRONTEND_URL', '').rsplit('/', 1)[0]  # Get base URL
        if base:
            frontend_url = f"{base}/{frontend_url.lstrip('/')}"
        else:
            frontend_url = f"/static/index.html"

    sep = '&' if '?' in frontend_url else '?'
    return RedirectResponse(url=f"{frontend_url}{sep}quickbooks=connected", status_code=302)


def get_qb_access_token(user_id: int, db: Session) -> tuple[str, str]:
    """Get valid QuickBooks access token, refreshing if needed.

    For single-tenant CRM: tries user's token first, then falls back to any org token.
    """
    # Try user's token first, then any available token (org-wide sharing)
    qb_token = db.query(QuickBooksToken).filter(QuickBooksToken.user_id == user_id).first()
    if not qb_token:
        qb_token = db.query(QuickBooksToken).first()  # Fallback to any org token
    if not qb_token:
        raise HTTPException(status_code=400, detail="QuickBooks not connected. Visit /quickbooks/connect first.")

    now = dt.datetime.now(dt.timezone.utc)

    # Check if refresh token expired
    if qb_token.refresh_token_expires_at < now:
        db.delete(qb_token)
        db.commit()
        raise HTTPException(status_code=400, detail="QuickBooks authorization expired. Please reconnect.")

    # Refresh access token if expired
    if qb_token.access_token_expires_at < now:
        resp = requests.post(
            QB_TOKEN_URL,
            auth=(get_qb_client_id(), get_qb_client_secret()),
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
    """Check QuickBooks connection status (org-wide for single-tenant CRM)."""
    # For single-tenant CRM: check user's token first, then any org token
    qb_token = db.query(QuickBooksToken).filter(QuickBooksToken.user_id == current_user.id).first()
    if not qb_token:
        qb_token = db.query(QuickBooksToken).first()  # Fallback to any org token

    if not qb_token:
        print(f"[QB Status] No tokens in database for org")
        return {"connected": False}
    print(f"[QB Status] Found org token, realm_id={qb_token.realm_id}")

    now = dt.datetime.now(dt.timezone.utc)
    return {
        "connected": True,
        "realm_id": qb_token.realm_id,
        "access_token_valid": qb_token.access_token_expires_at > now,
        "refresh_token_valid": qb_token.refresh_token_expires_at > now,
    }


@app.get("/quickbooks/debug")
def quickbooks_debug(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Debug: Show all QB tokens in database."""
    all_tokens = db.query(QuickBooksToken).all()
    return {
        "current_user_id": current_user.id,
        "all_tokens": [{"user_id": t.user_id, "realm_id": t.realm_id, "created": str(t.access_token_expires_at)} for t in all_tokens]
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
        f"{get_qb_api_base()}/v3/company/{realm_id}/query",
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
        f"{get_qb_api_base()}/v3/company/{realm_id}/customer",
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
        f"{get_qb_api_base()}/v3/company/{realm_id}/query",
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
    now = dt.datetime.now(dt.timezone.utc)

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
                    now = dt.datetime.now(dt.timezone.utc)
                    if qb_token.access_token_expires_at < now:
                        resp = requests.post(
                            QB_TOKEN_URL,
                            auth=(get_qb_client_id(), get_qb_client_secret()),
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


# Routes - Google Drive Integration
@app.get("/google/connect")
def google_connect(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Initiate Google OAuth flow for Drive access."""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Google not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.")

    state = secrets.token_urlsafe(32)

    # Store state in database (works across multiple workers/restarts)
    db.query(OAuthState).filter(OAuthState.provider == 'google', OAuthState.user_id == current_user.id).delete()
    oauth_state = OAuthState(state=state, user_id=current_user.id, provider='google', redirect_uri=GOOGLE_REDIRECT_URI)
    db.add(oauth_state)
    db.commit()

    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'response_type': 'code',
        'scope': 'https://www.googleapis.com/auth/drive.readonly',
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'state': state,
        'access_type': 'offline',
        'prompt': 'consent',
    }
    auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
    return {"auth_url": auth_url}


@app.get("/google/callback")
def google_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: Session = Depends(get_db)
):
    """Handle Google OAuth callback."""
    oauth_state = db.query(OAuthState).filter(OAuthState.state == state, OAuthState.provider == 'google').first()
    if not oauth_state:
        raise HTTPException(status_code=400, detail="Invalid or expired state token")

    user_id = oauth_state.user_id

    # Delete used state
    db.delete(oauth_state)
    db.commit()

    # Exchange code for tokens
    resp = requests.post(
        GOOGLE_TOKEN_URL,
        data={
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': GOOGLE_REDIRECT_URI,
        },
        timeout=30
    )

    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {resp.text}")

    tokens = resp.json()
    now = dt.datetime.now(dt.timezone.utc)

    # Save or update tokens
    g_token = db.query(GoogleDriveToken).filter(GoogleDriveToken.user_id == user_id).first()
    if g_token:
        g_token.access_token = tokens['access_token']
        g_token.refresh_token = tokens.get('refresh_token', g_token.refresh_token)
        g_token.access_token_expires_at = now + dt.timedelta(seconds=tokens.get('expires_in', 3600))
    else:
        g_token = GoogleDriveToken(
            user_id=user_id,
            access_token=tokens['access_token'],
            refresh_token=tokens.get('refresh_token', ''),
            access_token_expires_at=now + dt.timedelta(seconds=tokens.get('expires_in', 3600)),
        )
        db.add(g_token)

    db.commit()
    return RedirectResponse(url="/?google=connected")


def get_google_access_token(user_id: int, db: Session) -> str:
    """Get valid Google access token, refreshing if needed."""
    g_token = db.query(GoogleDriveToken).filter(GoogleDriveToken.user_id == user_id).first()
    if not g_token:
        raise HTTPException(status_code=400, detail="Google Drive not connected. Visit /google/connect first.")

    now = dt.datetime.now(dt.timezone.utc)

    # Refresh access token if expired
    if g_token.access_token_expires_at < now:
        if not g_token.refresh_token:
            db.delete(g_token)
            db.commit()
            raise HTTPException(status_code=400, detail="Google authorization expired. Please reconnect.")

        resp = requests.post(
            GOOGLE_TOKEN_URL,
            data={
                'client_id': GOOGLE_CLIENT_ID,
                'client_secret': GOOGLE_CLIENT_SECRET,
                'refresh_token': g_token.refresh_token,
                'grant_type': 'refresh_token',
            },
            timeout=30
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to refresh Google token")

        tokens = resp.json()
        g_token.access_token = tokens['access_token']
        g_token.access_token_expires_at = now + dt.timedelta(seconds=tokens.get('expires_in', 3600))
        db.commit()

    return g_token.access_token


@app.get("/google/status")
def google_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Check Google Drive connection status."""
    g_token = db.query(GoogleDriveToken).filter(GoogleDriveToken.user_id == current_user.id).first()
    if not g_token:
        return {"connected": False}

    now = dt.datetime.now(dt.timezone.utc)
    return {
        "connected": True,
        "access_token_valid": g_token.access_token_expires_at > now,
    }


@app.delete("/google/disconnect")
def google_disconnect(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Disconnect Google Drive integration."""
    g_token = db.query(GoogleDriveToken).filter(GoogleDriveToken.user_id == current_user.id).first()
    if g_token:
        db.delete(g_token)
        db.commit()
    return {"ok": True}


@app.get("/google/drive/files")
def list_drive_files(
    folder_id: Optional[str] = Query(None, description="Folder ID (root if not specified)"),
    query: Optional[str] = Query(None, description="Search query"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List files from Google Drive (CSV, VCF, or spreadsheets in Downloads or specified folder)."""
    access_token = get_google_access_token(current_user.id, db)

    # Build query for contact-importable files
    q_parts = ["trashed = false"]
    if folder_id:
        q_parts.append(f"'{folder_id}' in parents")
    if query:
        q_parts.append(f"name contains '{query}'")

    # Look for CSV, VCF, or Google Sheets
    q_parts.append("(mimeType = 'text/csv' or mimeType = 'text/x-vcard' or mimeType = 'application/vnd.google-apps.spreadsheet' or name contains '.csv' or name contains '.vcf')")

    resp = requests.get(
        f"{GOOGLE_DRIVE_API}/files",
        headers={'Authorization': f'Bearer {access_token}'},
        params={
            'q': ' and '.join(q_parts),
            'fields': 'files(id,name,mimeType,modifiedTime,size)',
            'orderBy': 'modifiedTime desc',
            'pageSize': 50,
        },
        timeout=30
    )

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"Google Drive API error: {resp.text}")

    return resp.json()


@app.get("/google/drive/folders")
def list_drive_folders(
    parent_id: Optional[str] = Query(None, description="Parent folder ID (root if not specified)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List folders from Google Drive to help navigate."""
    access_token = get_google_access_token(current_user.id, db)

    q_parts = ["mimeType = 'application/vnd.google-apps.folder'", "trashed = false"]
    if parent_id:
        q_parts.append(f"'{parent_id}' in parents")
    else:
        q_parts.append("'root' in parents")

    resp = requests.get(
        f"{GOOGLE_DRIVE_API}/files",
        headers={'Authorization': f'Bearer {access_token}'},
        params={
            'q': ' and '.join(q_parts),
            'fields': 'files(id,name)',
            'orderBy': 'name',
            'pageSize': 100,
        },
        timeout=30
    )

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"Google Drive API error: {resp.text}")

    return resp.json()


@app.post("/google/drive/import/{file_id}")
def import_contacts_from_drive(
    file_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Import contacts from a Google Drive CSV or VCF file."""
    access_token = get_google_access_token(current_user.id, db)

    # Get file metadata
    meta_resp = requests.get(
        f"{GOOGLE_DRIVE_API}/files/{file_id}",
        headers={'Authorization': f'Bearer {access_token}'},
        params={'fields': 'id,name,mimeType'},
        timeout=30
    )

    if meta_resp.status_code != 200:
        raise HTTPException(status_code=404, detail="File not found in Drive")

    file_meta = meta_resp.json()
    mime_type = file_meta.get('mimeType', '')
    file_name = file_meta.get('name', '')

    # Download file content
    if mime_type == 'application/vnd.google-apps.spreadsheet':
        # Export Google Sheet as CSV
        download_resp = requests.get(
            f"{GOOGLE_DRIVE_API}/files/{file_id}/export",
            headers={'Authorization': f'Bearer {access_token}'},
            params={'mimeType': 'text/csv'},
            timeout=60
        )
    else:
        # Download regular file
        download_resp = requests.get(
            f"{GOOGLE_DRIVE_API}/files/{file_id}",
            headers={'Authorization': f'Bearer {access_token}'},
            params={'alt': 'media'},
            timeout=60
        )

    if download_resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Failed to download file: {download_resp.text}")

    content = download_resp.text

    # Parse based on file type
    imported = 0
    errors = []

    if file_name.endswith('.vcf') or 'vcard' in mime_type.lower():
        # Parse VCF (vCard) format
        contacts_data = _parse_vcard(content)
        for i, c in enumerate(contacts_data, start=1):
            try:
                if not c.get('first_name') and not c.get('last_name'):
                    errors.append(f"vCard {i}: No name found")
                    continue
                contact = Contact(
                    owner_id=current_user.id,
                    first_name=c.get('first_name', 'Unknown'),
                    last_name=c.get('last_name', ''),
                    email=c.get('email'),
                    phone=c.get('phone'),
                    company=c.get('company'),
                    address_line1=c.get('address'),
                )
                db.add(contact)
                imported += 1
            except Exception as e:
                errors.append(f"vCard {i}: {str(e)}")
    else:
        # Parse CSV
        reader = csv.DictReader(io.StringIO(content))
        for i, row in enumerate(reader, start=2):
            try:
                # Try common column name variations
                first_name = (row.get('first_name') or row.get('First Name') or
                              row.get('Given Name') or row.get('firstname') or '').strip()
                last_name = (row.get('last_name') or row.get('Last Name') or
                             row.get('Family Name') or row.get('lastname') or '').strip()

                # Handle "Name" as single field
                if not first_name and not last_name:
                    full_name = (row.get('Name') or row.get('name') or row.get('Full Name') or '').strip()
                    if full_name:
                        parts = full_name.split(' ', 1)
                        first_name = parts[0]
                        last_name = parts[1] if len(parts) > 1 else ''

                if not first_name:
                    errors.append(f"Row {i}: No name found")
                    continue

                email = (row.get('email') or row.get('Email') or row.get('E-mail 1 - Value') or
                         row.get('Email Address') or '').strip() or None
                phone = (row.get('phone') or row.get('Phone') or row.get('Phone 1 - Value') or
                         row.get('Mobile') or row.get('Phone Number') or '').strip() or None
                company = (row.get('company') or row.get('Company') or row.get('Organization 1 - Name') or
                           row.get('Organization') or '').strip() or None

                contact = Contact(
                    owner_id=current_user.id,
                    first_name=first_name,
                    last_name=last_name or first_name,
                    email=email,
                    phone=phone,
                    company=company,
                    address_line1=(row.get('address_line1') or row.get('Address') or
                                   row.get('Address 1 - Street') or '').strip() or None,
                    city=(row.get('city') or row.get('City') or row.get('Address 1 - City') or '').strip() or None,
                    state=(row.get('state') or row.get('State') or row.get('Address 1 - Region') or '').strip() or None,
                    postal_code=(row.get('postal_code') or row.get('Zip') or row.get('Address 1 - Postal Code') or '').strip() or None,
                    country=(row.get('country') or row.get('Country') or row.get('Address 1 - Country') or '').strip() or None,
                    notes=(row.get('notes') or row.get('Notes') or '').strip() or None,
                )
                db.add(contact)
                imported += 1
            except Exception as e:
                errors.append(f"Row {i}: {str(e)}")

    db.commit()
    return {"imported": imported, "errors": errors, "file_name": file_name}


def _parse_vcard(content: str) -> list:
    """Parse vCard format and return list of contact dicts."""
    contacts = []
    current = {}

    for line in content.split('\n'):
        line = line.strip()
        if line == 'BEGIN:VCARD':
            current = {}
        elif line == 'END:VCARD':
            if current:
                contacts.append(current)
            current = {}
        elif ':' in line:
            key, value = line.split(':', 1)
            key = key.split(';')[0].upper()  # Handle parameters like TEL;TYPE=CELL
            if key == 'FN':
                # Full name
                parts = value.split(' ', 1)
                current['first_name'] = parts[0]
                current['last_name'] = parts[1] if len(parts) > 1 else ''
            elif key == 'N':
                # Structured name: last;first;middle;prefix;suffix
                parts = value.split(';')
                if len(parts) >= 2:
                    current['last_name'] = parts[0]
                    current['first_name'] = parts[1]
            elif key == 'EMAIL':
                current['email'] = value
            elif key == 'TEL':
                current['phone'] = value
            elif key == 'ORG':
                current['company'] = value.replace(';', ' ').strip()
            elif key == 'ADR':
                # Structured address: PO;ext;street;city;region;postal;country
                parts = value.split(';')
                if len(parts) >= 3:
                    current['address'] = parts[2]

    return contacts


# Routes - Inventory
@app.post("/inventory", response_model=InventoryItemOut)
def create_inventory_item(
    item_data: InventoryItemCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new inventory item."""
    # Check for duplicate SKU
    existing = db.query(InventoryItem).filter(
        InventoryItem.owner_id == current_user.id,
        InventoryItem.sku == item_data.sku
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"SKU '{item_data.sku}' already exists")

    item = InventoryItem(owner_id=current_user.id, **item_data.model_dump())
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@app.get("/inventory", response_model=List[InventoryItemOut])
def list_inventory(
    search: Optional[str] = Query(None, description="Search in name, SKU, brand"),
    category: Optional[str] = Query(None),
    brand: Optional[str] = Query(None),
    low_stock: bool = Query(False, description="Only show items at or below reorder level"),
    active_only: bool = Query(True, description="Only show active items"),
    sort_by: str = Query("name", description="Sort field"),
    sort_order: str = Query("asc", description="Sort order: asc or desc"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List inventory items with filters."""
    query = db.query(InventoryItem).filter(InventoryItem.owner_id == current_user.id)

    if active_only:
        query = query.filter(InventoryItem.is_active == True)
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                InventoryItem.name.ilike(search_term),
                InventoryItem.sku.ilike(search_term),
                InventoryItem.brand.ilike(search_term),
                InventoryItem.description.ilike(search_term),
            )
        )
    if category:
        query = query.filter(InventoryItem.category.ilike(f"%{category}%"))
    if brand:
        query = query.filter(InventoryItem.brand.ilike(f"%{brand}%"))
    if low_stock:
        query = query.filter(InventoryItem.quantity <= InventoryItem.reorder_level)

    sort_column = getattr(InventoryItem, sort_by, InventoryItem.name)
    if sort_order.lower() == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    return query.offset(skip).limit(limit).all()


@app.get("/inventory/{item_id}", response_model=InventoryItemOut)
def get_inventory_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a single inventory item."""
    item = db.query(InventoryItem).filter(
        InventoryItem.id == item_id,
        InventoryItem.owner_id == current_user.id
    ).first()
    if not item:
        raise HTTPException(status_code=404, detail="Inventory item not found")
    return item


@app.patch("/inventory/{item_id}", response_model=InventoryItemOut)
def update_inventory_item(
    item_id: int,
    item_data: InventoryItemUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update an inventory item."""
    item = db.query(InventoryItem).filter(
        InventoryItem.id == item_id,
        InventoryItem.owner_id == current_user.id
    ).first()
    if not item:
        raise HTTPException(status_code=404, detail="Inventory item not found")

    update_data = item_data.model_dump(exclude_unset=True)

    # Check SKU uniqueness if changing
    if 'sku' in update_data and update_data['sku'] != item.sku:
        existing = db.query(InventoryItem).filter(
            InventoryItem.owner_id == current_user.id,
            InventoryItem.sku == update_data['sku']
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail=f"SKU '{update_data['sku']}' already exists")

    for key, value in update_data.items():
        setattr(item, key, value)

    db.commit()
    db.refresh(item)
    return item


@app.delete("/inventory/{item_id}")
def delete_inventory_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete an inventory item."""
    item = db.query(InventoryItem).filter(
        InventoryItem.id == item_id,
        InventoryItem.owner_id == current_user.id
    ).first()
    if not item:
        raise HTTPException(status_code=404, detail="Inventory item not found")
    db.delete(item)
    db.commit()
    return {"ok": True}


# Inventory Transactions
@app.post("/inventory/{item_id}/transactions", response_model=InventoryTransactionOut)
def create_inventory_transaction(
    item_id: int,
    txn_data: InventoryTransactionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Record a stock transaction (receive, sell, adjust, etc.)."""
    item = db.query(InventoryItem).filter(
        InventoryItem.id == item_id,
        InventoryItem.owner_id == current_user.id
    ).first()
    if not item:
        raise HTTPException(status_code=404, detail="Inventory item not found")

    # Validate transaction type
    valid_types = ['receive', 'sell', 'adjust', 'transfer', 'return']
    if txn_data.transaction_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid transaction type. Use: {valid_types}")

    # Determine quantity change
    qty_change = txn_data.quantity
    if txn_data.transaction_type == 'sell':
        qty_change = -abs(txn_data.quantity)
    elif txn_data.transaction_type in ['receive', 'return']:
        qty_change = abs(txn_data.quantity)

    # Check for negative stock on sell
    if qty_change < 0 and (item.quantity + qty_change) < 0:
        raise HTTPException(status_code=400, detail=f"Insufficient stock. Available: {item.quantity}")

    txn = InventoryTransaction(
        item_id=item_id,
        owner_id=current_user.id,
        transaction_type=txn_data.transaction_type,
        quantity=qty_change,
        unit_cost=txn_data.unit_cost,
        reference=txn_data.reference,
        notes=txn_data.notes,
        contact_id=txn_data.contact_id,
    )
    db.add(txn)

    # Update item quantity
    item.quantity += qty_change

    db.commit()
    db.refresh(txn)
    return txn


@app.get("/inventory/{item_id}/transactions", response_model=List[InventoryTransactionOut])
def list_inventory_transactions(
    item_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List transactions for an inventory item."""
    item = db.query(InventoryItem).filter(
        InventoryItem.id == item_id,
        InventoryItem.owner_id == current_user.id
    ).first()
    if not item:
        raise HTTPException(status_code=404, detail="Inventory item not found")

    return db.query(InventoryTransaction).filter(
        InventoryTransaction.item_id == item_id
    ).order_by(InventoryTransaction.created_at.desc()).offset(skip).limit(limit).all()


@app.get("/inventory/stats/summary")
def get_inventory_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get inventory summary stats."""
    items = db.query(InventoryItem).filter(
        InventoryItem.owner_id == current_user.id,
        InventoryItem.is_active == True
    ).all()

    total_items = len(items)
    total_quantity = sum(i.quantity for i in items)
    total_value = sum((i.quantity * (i.cost or 0)) for i in items)
    low_stock_count = sum(1 for i in items if i.quantity <= i.reorder_level)
    out_of_stock = sum(1 for i in items if i.quantity <= 0)

    return {
        "total_items": total_items,
        "total_quantity": total_quantity,
        "total_value": round(total_value, 2),
        "low_stock_count": low_stock_count,
        "out_of_stock": out_of_stock
    }


# QuickBooks Inventory Sync
@app.get("/quickbooks/items")
def list_quickbooks_items(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List items from QuickBooks."""
    access_token, realm_id = get_qb_access_token(current_user.id, db)

    resp = requests.get(
        f"{get_qb_api_base()}/v3/company/{realm_id}/query",
        headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        },
        params={'query': 'SELECT * FROM Item MAXRESULTS 500'},
        timeout=30
    )

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"QuickBooks API error: {resp.text}")

    data = resp.json()
    items = data.get('QueryResponse', {}).get('Item', [])
    return {"items": items}


@app.post("/quickbooks/import-items")
def import_quickbooks_items(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Import QuickBooks items (all types)."""
    access_token, realm_id = get_qb_access_token(current_user.id, db)

    resp = requests.get(
        f"{get_qb_api_base()}/v3/company/{realm_id}/query",
        headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        },
        params={'query': 'SELECT * FROM Item MAXRESULTS 500'},
        timeout=30
    )

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"QuickBooks API error: {resp.text}")

    data = resp.json()
    qb_items = data.get('QueryResponse', {}).get('Item', [])

    imported = 0
    updated = 0
    for qb_item in qb_items:
        qb_id = qb_item.get('Id')
        sku = qb_item.get('Sku') or qb_item.get('Name', f'QB-{qb_id}')
        name = qb_item.get('Name', 'Unknown')

        # Check if already imported
        existing = db.query(InventoryItem).filter(
            InventoryItem.owner_id == current_user.id,
            InventoryItem.qb_item_id == qb_id
        ).first()

        if existing:
            # Update existing
            existing.name = name
            existing.quantity = int(qb_item.get('QtyOnHand', 0))
            existing.cost = qb_item.get('PurchaseCost')
            existing.price = qb_item.get('UnitPrice')
            updated += 1
        else:
            # Check SKU collision
            sku_exists = db.query(InventoryItem).filter(
                InventoryItem.owner_id == current_user.id,
                InventoryItem.sku == sku
            ).first()
            if sku_exists:
                sku = f"{sku}-QB{qb_id}"

            item = InventoryItem(
                owner_id=current_user.id,
                sku=sku,
                name=name,
                description=qb_item.get('Description'),
                quantity=int(qb_item.get('QtyOnHand', 0)),
                cost=qb_item.get('PurchaseCost'),
                price=qb_item.get('UnitPrice'),
                qb_item_id=qb_id,
            )
            db.add(item)
            imported += 1

    db.commit()
    return {"imported": imported, "updated": updated, "total_qb_items": len(qb_items)}


@app.post("/inventory/{item_id}/sync-to-qb")
def sync_inventory_to_quickbooks(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Sync an inventory item to QuickBooks."""
    item = db.query(InventoryItem).filter(
        InventoryItem.id == item_id,
        InventoryItem.owner_id == current_user.id
    ).first()
    if not item:
        raise HTTPException(status_code=404, detail="Inventory item not found")

    access_token, realm_id = get_qb_access_token(current_user.id, db)

    qb_item_data = {
        "Name": item.name[:100],  # QB limit
        "Type": "Inventory",
        "Sku": item.sku,
        "Description": item.description,
        "QtyOnHand": item.quantity,
        "TrackQtyOnHand": True,
        "InvStartDate": dt.date.today().isoformat(),
    }
    if item.cost:
        qb_item_data["PurchaseCost"] = item.cost
    if item.price:
        qb_item_data["UnitPrice"] = item.price

    # Need income and expense accounts for inventory items
    # This is a simplified version - real implementation needs account refs
    resp = requests.post(
        f"{get_qb_api_base()}/v3/company/{realm_id}/item",
        headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
        json=qb_item_data,
        timeout=30
    )

    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=resp.status_code, detail=f"QuickBooks API error: {resp.text}")

    qb_result = resp.json().get('Item', {})
    item.qb_item_id = qb_result.get('Id')
    db.commit()

    return {"ok": True, "qb_item_id": item.qb_item_id}


# =============================================================================
# SUPPLIER ENDPOINTS
# =============================================================================

def _simple_encrypt(text: str) -> str:
    """Simple XOR encryption for portal passwords (use proper encryption in production)."""
    key = JWT_SECRET[:32].ljust(32, '0')
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text)).encode('latin-1').hex()


def _simple_decrypt(encrypted_hex: str) -> str:
    """Decrypt XOR encrypted text."""
    key = JWT_SECRET[:32].ljust(32, '0')
    encrypted = bytes.fromhex(encrypted_hex).decode('latin-1')
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(encrypted))


@app.get("/suppliers", response_model=List[SupplierOut])
def list_suppliers(
    active_only: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all suppliers."""
    query = db.query(Supplier).filter(Supplier.owner_id == current_user.id)
    if active_only:
        query = query.filter(Supplier.is_active == True)
    suppliers = query.order_by(Supplier.name).all()

    result = []
    for s in suppliers:
        result.append(SupplierOut(
            id=s.id,
            name=s.name,
            code=s.code,
            contact_name=s.contact_name,
            phone=s.phone,
            email=s.email,
            address=s.address,
            city=s.city,
            website=s.website,
            portal_url=s.portal_url,
            portal_username=s.portal_username,
            has_credentials=bool(s.portal_password_encrypted),
            notes=s.notes,
            is_active=s.is_active,
            created_at=s.created_at
        ))
    return result


@app.post("/suppliers", response_model=SupplierOut)
def create_supplier(
    data: SupplierCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new supplier."""
    # Check for duplicate name
    existing = db.query(Supplier).filter(
        Supplier.owner_id == current_user.id,
        Supplier.name == data.name
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Supplier with this name already exists")

    supplier = Supplier(
        owner_id=current_user.id,
        name=data.name,
        code=data.code,
        contact_name=data.contact_name,
        phone=data.phone,
        email=data.email,
        address=data.address,
        city=data.city,
        website=data.website,
        portal_url=data.portal_url,
        portal_username=data.portal_username,
        portal_password_encrypted=_simple_encrypt(data.portal_password) if data.portal_password else None,
        notes=data.notes
    )
    db.add(supplier)
    db.commit()
    db.refresh(supplier)

    return SupplierOut(
        id=supplier.id,
        name=supplier.name,
        code=supplier.code,
        contact_name=supplier.contact_name,
        phone=supplier.phone,
        email=supplier.email,
        address=supplier.address,
        city=supplier.city,
        website=supplier.website,
        portal_url=supplier.portal_url,
        portal_username=supplier.portal_username,
        has_credentials=bool(supplier.portal_password_encrypted),
        notes=supplier.notes,
        is_active=supplier.is_active,
        created_at=supplier.created_at
    )


@app.get("/suppliers/{supplier_id}", response_model=SupplierOut)
def get_supplier(
    supplier_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a single supplier."""
    supplier = db.query(Supplier).filter(
        Supplier.id == supplier_id,
        Supplier.owner_id == current_user.id
    ).first()
    if not supplier:
        raise HTTPException(status_code=404, detail="Supplier not found")

    return SupplierOut(
        id=supplier.id,
        name=supplier.name,
        code=supplier.code,
        contact_name=supplier.contact_name,
        phone=supplier.phone,
        email=supplier.email,
        address=supplier.address,
        city=supplier.city,
        website=supplier.website,
        portal_url=supplier.portal_url,
        portal_username=supplier.portal_username,
        has_credentials=bool(supplier.portal_password_encrypted),
        notes=supplier.notes,
        is_active=supplier.is_active,
        created_at=supplier.created_at
    )


@app.patch("/suppliers/{supplier_id}", response_model=SupplierOut)
def update_supplier(
    supplier_id: int,
    data: SupplierUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a supplier."""
    supplier = db.query(Supplier).filter(
        Supplier.id == supplier_id,
        Supplier.owner_id == current_user.id
    ).first()
    if not supplier:
        raise HTTPException(status_code=404, detail="Supplier not found")

    update_data = data.model_dump(exclude_unset=True)
    if 'portal_password' in update_data:
        pwd = update_data.pop('portal_password')
        if pwd:
            supplier.portal_password_encrypted = _simple_encrypt(pwd)
        else:
            supplier.portal_password_encrypted = None

    for key, value in update_data.items():
        setattr(supplier, key, value)

    db.commit()
    db.refresh(supplier)

    return SupplierOut(
        id=supplier.id,
        name=supplier.name,
        code=supplier.code,
        contact_name=supplier.contact_name,
        phone=supplier.phone,
        email=supplier.email,
        address=supplier.address,
        city=supplier.city,
        website=supplier.website,
        portal_url=supplier.portal_url,
        portal_username=supplier.portal_username,
        has_credentials=bool(supplier.portal_password_encrypted),
        notes=supplier.notes,
        is_active=supplier.is_active,
        created_at=supplier.created_at
    )


@app.delete("/suppliers/{supplier_id}")
def delete_supplier(
    supplier_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a supplier."""
    supplier = db.query(Supplier).filter(
        Supplier.id == supplier_id,
        Supplier.owner_id == current_user.id
    ).first()
    if not supplier:
        raise HTTPException(status_code=404, detail="Supplier not found")

    db.delete(supplier)
    db.commit()
    return {"ok": True}


# =============================================================================
# PURCHASE ORDER ENDPOINTS
# =============================================================================

def _generate_order_number(db: Session, user_id: int) -> str:
    """Generate a unique PO number like PO-2026-0001."""
    year = dt.datetime.now().year
    prefix = f"PO-{year}-"

    last_order = db.query(PurchaseOrder).filter(
        PurchaseOrder.owner_id == user_id,
        PurchaseOrder.order_number.like(f"{prefix}%")
    ).order_by(PurchaseOrder.order_number.desc()).first()

    if last_order:
        try:
            last_num = int(last_order.order_number.split('-')[-1])
            next_num = last_num + 1
        except ValueError:
            next_num = 1
    else:
        next_num = 1

    return f"{prefix}{next_num:04d}"


@app.get("/orders", response_model=List[PurchaseOrderOut])
def list_orders(
    status: Optional[str] = None,
    supplier_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List purchase orders."""
    query = db.query(PurchaseOrder).filter(PurchaseOrder.owner_id == current_user.id)

    if status:
        query = query.filter(PurchaseOrder.status == status)
    if supplier_id:
        query = query.filter(PurchaseOrder.supplier_id == supplier_id)

    orders = query.order_by(PurchaseOrder.created_at.desc()).all()

    result = []
    for order in orders:
        items = [PurchaseOrderItemOut(
            id=item.id,
            inventory_item_id=item.inventory_item_id,
            sku=item.sku,
            description=item.description,
            quantity=item.quantity,
            unit_cost=item.unit_cost,
            total=item.total,
            received_qty=item.received_qty
        ) for item in order.items]

        result.append(PurchaseOrderOut(
            id=order.id,
            supplier_id=order.supplier_id,
            supplier_name=order.supplier.name,
            order_number=order.order_number,
            status=order.status,
            subtotal=order.subtotal,
            tax=order.tax,
            shipping=order.shipping,
            total=order.total,
            notes=order.notes,
            submitted_at=order.submitted_at,
            expected_delivery=order.expected_delivery,
            received_at=order.received_at,
            created_at=order.created_at,
            items=items
        ))

    return result


@app.post("/orders", response_model=PurchaseOrderOut)
def create_order(
    data: PurchaseOrderCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new purchase order."""
    # Verify supplier exists
    supplier = db.query(Supplier).filter(
        Supplier.id == data.supplier_id,
        Supplier.owner_id == current_user.id
    ).first()
    if not supplier:
        raise HTTPException(status_code=404, detail="Supplier not found")

    order_number = _generate_order_number(db, current_user.id)

    subtotal = sum(item.quantity * item.unit_cost for item in data.items)

    order = PurchaseOrder(
        owner_id=current_user.id,
        supplier_id=data.supplier_id,
        order_number=order_number,
        status='draft',
        subtotal=subtotal,
        total=subtotal,  # Tax/shipping added later
        notes=data.notes
    )
    db.add(order)
    db.flush()  # Get the order ID

    for item_data in data.items:
        order_item = PurchaseOrderItem(
            order_id=order.id,
            inventory_item_id=item_data.inventory_item_id,
            sku=item_data.sku,
            description=item_data.description,
            quantity=item_data.quantity,
            unit_cost=item_data.unit_cost,
            total=item_data.quantity * item_data.unit_cost
        )
        db.add(order_item)

    db.commit()
    db.refresh(order)

    items = [PurchaseOrderItemOut(
        id=item.id,
        inventory_item_id=item.inventory_item_id,
        sku=item.sku,
        description=item.description,
        quantity=item.quantity,
        unit_cost=item.unit_cost,
        total=item.total,
        received_qty=item.received_qty
    ) for item in order.items]

    return PurchaseOrderOut(
        id=order.id,
        supplier_id=order.supplier_id,
        supplier_name=supplier.name,
        order_number=order.order_number,
        status=order.status,
        subtotal=order.subtotal,
        tax=order.tax,
        shipping=order.shipping,
        total=order.total,
        notes=order.notes,
        submitted_at=order.submitted_at,
        expected_delivery=order.expected_delivery,
        received_at=order.received_at,
        created_at=order.created_at,
        items=items
    )


@app.get("/orders/{order_id}", response_model=PurchaseOrderOut)
def get_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a single purchase order."""
    order = db.query(PurchaseOrder).filter(
        PurchaseOrder.id == order_id,
        PurchaseOrder.owner_id == current_user.id
    ).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    items = [PurchaseOrderItemOut(
        id=item.id,
        inventory_item_id=item.inventory_item_id,
        sku=item.sku,
        description=item.description,
        quantity=item.quantity,
        unit_cost=item.unit_cost,
        total=item.total,
        received_qty=item.received_qty
    ) for item in order.items]

    return PurchaseOrderOut(
        id=order.id,
        supplier_id=order.supplier_id,
        supplier_name=order.supplier.name,
        order_number=order.order_number,
        status=order.status,
        subtotal=order.subtotal,
        tax=order.tax,
        shipping=order.shipping,
        total=order.total,
        notes=order.notes,
        submitted_at=order.submitted_at,
        expected_delivery=order.expected_delivery,
        received_at=order.received_at,
        created_at=order.created_at,
        items=items
    )


@app.post("/orders/{order_id}/submit")
def submit_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Submit an order (mark as submitted)."""
    order = db.query(PurchaseOrder).filter(
        PurchaseOrder.id == order_id,
        PurchaseOrder.owner_id == current_user.id
    ).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if order.status != 'draft':
        raise HTTPException(status_code=400, detail="Only draft orders can be submitted")

    order.status = 'submitted'
    order.submitted_at = dt.datetime.now(dt.timezone.utc)
    db.commit()

    return {"ok": True, "order_number": order.order_number, "status": order.status}


@app.post("/orders/{order_id}/receive")
def receive_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Mark order as received and update inventory."""
    order = db.query(PurchaseOrder).filter(
        PurchaseOrder.id == order_id,
        PurchaseOrder.owner_id == current_user.id
    ).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if order.status == 'received':
        raise HTTPException(status_code=400, detail="Order already received")

    # Update inventory for each item
    for order_item in order.items:
        if order_item.inventory_item_id:
            inv_item = db.query(InventoryItem).filter(
                InventoryItem.id == order_item.inventory_item_id,
                InventoryItem.owner_id == current_user.id
            ).first()
            if inv_item:
                inv_item.quantity += order_item.quantity
                inv_item.cost = order_item.unit_cost  # Update cost

                # Create transaction record
                txn = InventoryTransaction(
                    item_id=inv_item.id,
                    owner_id=current_user.id,
                    transaction_type='receive',
                    quantity=order_item.quantity,
                    unit_cost=order_item.unit_cost,
                    reference=order.order_number,
                    notes=f"Received from {order.supplier.name}"
                )
                db.add(txn)

        order_item.received_qty = order_item.quantity

    order.status = 'received'
    order.received_at = dt.datetime.now(dt.timezone.utc)
    db.commit()

    return {"ok": True, "order_number": order.order_number, "status": order.status}


@app.delete("/orders/{order_id}")
def delete_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a draft order."""
    order = db.query(PurchaseOrder).filter(
        PurchaseOrder.id == order_id,
        PurchaseOrder.owner_id == current_user.id
    ).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if order.status != 'draft':
        raise HTTPException(status_code=400, detail="Only draft orders can be deleted")

    db.delete(order)
    db.commit()
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
