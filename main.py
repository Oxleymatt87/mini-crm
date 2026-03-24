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


class SupplierCatalog(Base):
    """Cached supplier product catalog — refreshed weekly via POST /stock/refresh-all."""
    __tablename__ = 'supplier_catalog'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    supplier_id: Mapped[int] = mapped_column(ForeignKey('suppliers.id', ondelete='CASCADE'), index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), index=True)
    sku: Mapped[str] = mapped_column(String(100))
    brand: Mapped[Optional[str]] = mapped_column(String(100))
    model: Mapped[Optional[str]] = mapped_column(String(255))
    size: Mapped[Optional[str]] = mapped_column(String(50))
    cost: Mapped[Optional[str]] = mapped_column(String(50))
    fet: Mapped[Optional[str]] = mapped_column(String(50))
    availability: Mapped[Optional[str]] = mapped_column(String(100))
    last_updated: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=dt.datetime.utcnow)


Index('ix_catalog_supplier_sku', SupplierCatalog.supplier_id, SupplierCatalog.sku)


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
    qb_item_id: Optional[str] = None


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

    # Start background cron: refresh supplier catalogs every Monday at 05:00 Central
    threading.Thread(target=_stock_cron_thread, daemon=True, name="stock-cron").start()
    print("Stock catalog cron thread started (runs every Sunday at 06:00 Central, refreshes QBO tokens + all supplier costs).")


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


@app.post("/inventory/deduplicate")
def deduplicate_inventory(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Remove duplicate CRM inventory items that share brand+name+size.
    Keeps the item that has a qb_item_id; if neither or both do, keeps the
    lower primary-key (original) row. Returns counts of removed duplicates."""
    from collections import defaultdict

    items = db.query(InventoryItem).filter(
        InventoryItem.owner_id == current_user.id
    ).order_by(InventoryItem.id).all()

    # Group by normalised (brand, name, size)
    groups: dict = defaultdict(list)
    for it in items:
        key = (
            (it.brand or "").strip().lower(),
            (it.name or "").strip().lower(),
            (it.size or "").strip().lower(),
        )
        groups[key].append(it)

    removed = []
    kept = []

    for key, group in groups.items():
        if len(group) < 2:
            continue
        # Pick winner: prefer item with qb_item_id, then lowest id
        winner = next((it for it in group if it.qb_item_id), group[0])
        losers = [it for it in group if it.id != winner.id]
        for loser in losers:
            removed.append({"id": loser.id, "sku": loser.sku, "name": loser.name,
                            "had_qb_id": bool(loser.qb_item_id)})
            db.delete(loser)
        kept.append({"id": winner.id, "sku": winner.sku, "name": winner.name,
                     "qb_item_id": winner.qb_item_id})

    db.commit()
    return {"removed": len(removed), "details_removed": removed, "kept_count": len(kept)}


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


@app.get("/inventory/stats/sales-rank")
def get_inventory_sales_rank(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Return total qty sold per inventory item (sum of sell transactions)."""
    from sqlalchemy import func as sqlfunc
    rows = (
        db.query(InventoryTransaction.item_id, sqlfunc.sum(InventoryTransaction.quantity).label("total"))
        .filter(
            InventoryTransaction.owner_id == current_user.id,
            InventoryTransaction.transaction_type == "sell",
        )
        .group_by(InventoryTransaction.item_id)
        .all()
    )
    return {str(row.item_id): abs(int(row.total or 0)) for row in rows}


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


@app.post("/quickbooks/rematch-items")
def rematch_qbo_items(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Re-match CRM inventory items to real QBO item IDs by fuzzy brand+name/size match.
    For CRM items with no QBO match, create them in QBO and store the new ID.
    Returns counts of matched, created, and failed items."""
    import difflib

    access_token, realm_id = get_qb_access_token(current_user.id, db)

    # 1. Pull all QBO items (up to 500)
    resp = requests.get(
        f"{get_qb_api_base()}/v3/company/{realm_id}/query",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        params={"query": "SELECT * FROM Item MAXRESULTS 500"},
        timeout=30,
    )
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"QBO API error: {resp.text[:300]}")

    qbo_items = resp.json().get("QueryResponse", {}).get("Item", [])

    # Build lookup keys: normalised name → qbo item
    def _norm(s: str) -> str:
        return re.sub(r"[^a-z0-9]", "", (s or "").lower())

    qbo_by_name: dict[str, dict] = {}
    for qi in qbo_items:
        key = _norm(qi.get("Name", ""))
        if key:
            qbo_by_name[key] = qi

    qbo_names = list(qbo_by_name.keys())

    crm_items = db.query(InventoryItem).filter(
        InventoryItem.owner_id == current_user.id,
        InventoryItem.is_active == True,
    ).all()

    matched = 0
    created = 0
    failed = 0
    details = []

    for item in crm_items:
        # Build a search key from brand + size or brand + name
        candidate_keys = []
        if item.brand and item.size:
            candidate_keys.append(_norm(f"{item.brand} {item.size}"))
        if item.brand and item.name:
            candidate_keys.append(_norm(f"{item.brand} {item.name}"))
        candidate_keys.append(_norm(item.name))

        best_match = None
        best_score = 0.0
        for ck in candidate_keys:
            hits = difflib.get_close_matches(ck, qbo_names, n=1, cutoff=0.65)
            if hits:
                score = difflib.SequenceMatcher(None, ck, hits[0]).ratio()
                if score > best_score:
                    best_score = score
                    best_match = qbo_by_name[hits[0]]

        if best_match:
            old_id = item.qb_item_id
            item.qb_item_id = best_match["Id"]
            db.commit()
            matched += 1
            details.append({"sku": item.sku, "name": item.name, "action": "matched",
                            "qb_id": item.qb_item_id, "qb_name": best_match.get("Name"), "score": round(best_score, 3)})
        else:
            # Create in QBO
            qb_data = {
                "Name": item.name[:100],
                "Type": "NonInventory",
                "IncomeAccountRef": {"value": "7", "name": "Sales"},
                "ExpenseAccountRef": {"value": "9", "name": "Cost of Goods Sold"},
            }
            if item.sku:
                qb_data["Sku"] = item.sku
            if item.description:
                qb_data["Description"] = item.description[:4000]
            if item.cost:
                qb_data["PurchaseCost"] = item.cost
            if item.price:
                qb_data["UnitPrice"] = item.price
            try:
                cr = requests.post(
                    f"{get_qb_api_base()}/v3/company/{realm_id}/item",
                    headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json",
                             "Content-Type": "application/json"},
                    json=qb_data, timeout=30,
                )
                if cr.status_code in (200, 201):
                    new_id = cr.json().get("Item", {}).get("Id")
                    item.qb_item_id = new_id
                    db.commit()
                    created += 1
                    details.append({"sku": item.sku, "name": item.name, "action": "created", "qb_id": new_id})
                else:
                    failed += 1
                    details.append({"sku": item.sku, "name": item.name, "action": "failed", "error": cr.text[:200]})
            except Exception as exc:
                failed += 1
                details.append({"sku": item.sku, "name": item.name, "action": "failed", "error": str(exc)[:200]})

    return {
        "total_crm": len(crm_items),
        "total_qbo": len(qbo_items),
        "matched": matched,
        "created": created,
        "failed": failed,
        "details": details,
    }


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
        sku = (qb_item.get('Sku') or qb_item.get('Name', f'QB-{qb_id}'))[:100]
        name = qb_item.get('Name', 'Unknown')[:255]

        # Check if already imported
        existing = db.query(InventoryItem).filter(
            InventoryItem.owner_id == current_user.id,
            InventoryItem.qb_item_id == qb_id
        ).first()

        qty = qb_item.get('QtyOnHand') or 0

        if existing:
            # Update existing
            existing.name = name
            existing.quantity = int(qty)
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
                quantity=int(qty),
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
    """Sync an inventory item to QuickBooks as NonInventory."""
    item = db.query(InventoryItem).filter(
        InventoryItem.id == item_id,
        InventoryItem.owner_id == current_user.id
    ).first()
    if not item:
        raise HTTPException(status_code=404, detail="Inventory item not found")

    access_token, realm_id = get_qb_access_token(current_user.id, db)

    qb_item_data = {
        "Name": item.name[:100],
        "Type": "NonInventory",
        "Sku": item.sku or "",
        "Description": item.description or item.name,
        "IncomeAccountRef": {"value": "7", "name": "Sales"},
        "ExpenseAccountRef": {"value": "9", "name": "Cost of Goods Sold"},
    }
    if item.cost:
        qb_item_data["PurchaseCost"] = item.cost
    if item.price:
        qb_item_data["UnitPrice"] = item.price

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
# FIREBASE INVENTORY SYNC
# =============================================================================

FIREBASE_API_KEY = "AIzaSyDdxP9prJjiFFeJ1XGZewkzstgxf7Ciy4E"
FIREBASE_PROJECT_ID = "inventory-setup-b3f20"


@app.post("/firebase/sync-inventory")
def sync_firebase_inventory(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Sync inventory from Firebase Oxley Tire app."""
    # Authenticate with Firebase
    auth_resp = requests.post(
        f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}",
        json={
            "email": "moxley@oxleytireinc.com",
            "password": "Silver28!!",
            "returnSecureToken": True
        },
        timeout=30
    )
    if auth_resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Firebase auth failed: {auth_resp.text}")

    id_token = auth_resp.json().get("idToken")

    # Fetch items from Firestore (collection is "items")
    firestore_resp = requests.get(
        f"https://firestore.googleapis.com/v1/projects/{FIREBASE_PROJECT_ID}/databases/(default)/documents/items",
        headers={"Authorization": f"Bearer {id_token}"},
        timeout=30
    )
    if firestore_resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Firestore fetch failed: {firestore_resp.text}")

    docs = firestore_resp.json().get("documents", [])
    imported = 0
    updated = 0

    for doc in docs:
        fields = doc.get("fields", {})
        firebase_id = doc.get("name", "").split("/")[-1]

        # Extract fields (Firestore uses typed values)
        def get_val(f, default=None):
            if f not in fields:
                return default
            v = fields[f]
            if "stringValue" in v:
                return v["stringValue"]
            if "integerValue" in v:
                return int(v["integerValue"])
            if "doubleValue" in v:
                return float(v["doubleValue"])
            if "booleanValue" in v:
                return v["booleanValue"]
            return default

        sku = get_val("sku") or firebase_id
        brand = get_val("brand") or ""
        model = get_val("model") or ""
        size = get_val("size") or ""
        position = get_val("position") or ""
        condition = get_val("condition") or ""
        # Build name from tire attributes
        name = f"{brand} {model} {size} {position} {condition}".strip() or sku
        cost = get_val("unitCost") or get_val("landedCost")
        price = get_val("landedCost")  # landed cost as sell price

        # Check if exists by SKU
        existing = db.query(InventoryItem).filter(
            InventoryItem.owner_id == current_user.id,
            InventoryItem.sku == sku[:100]
        ).first()

        if existing:
            existing.name = name[:255]
            if cost:
                existing.cost = float(cost)
            if price:
                existing.price = float(price)
            existing.brand = brand or existing.brand
            existing.size = size or existing.size
            existing.category = "tire"
            updated += 1
        else:
            item = InventoryItem(
                owner_id=current_user.id,
                sku=sku[:100],
                name=name[:255],
                description=f"{position} - {condition}",
                category="tire",
                brand=brand,
                size=size,
                quantity=0,
                cost=float(cost) if cost else None,
                price=float(price) if price else None,
            )
            db.add(item)
            imported += 1

    db.commit()
    return {"imported": imported, "updated": updated, "total_firebase_docs": len(docs)}


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



# === Version + Bulk QBO Sync ===
@app.get("/version")
def get_version():
    return {"version": "2026-03-21-v6"}

@app.post("/inventory/bulk-qb-sync")
def bulk_qb_sync(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    access_token, realm_id = get_qb_access_token(current_user.id, db)
    items = db.query(InventoryItem).filter(
        InventoryItem.owner_id == current_user.id,
        InventoryItem.is_active == True,
        InventoryItem.qb_item_id == None
    ).all()
    results = []
    for item in items:
        qb_data = {
            "Name": item.name[:100],
            "Type": "NonInventory",
            "Sku": item.sku or "",
            "Description": (item.description or item.name)[:4000],
            "IncomeAccountRef": {"value": "7", "name": "Sales"},
            "ExpenseAccountRef": {"value": "9", "name": "Cost of Goods Sold"},
        }
        if item.cost: qb_data["PurchaseCost"] = item.cost
        if item.price: qb_data["UnitPrice"] = item.price
        try:
            resp = requests.post(
                f"{QB_API_BASE}/v3/company/{realm_id}/item",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json", "Content-Type": "application/json"},
                json=qb_data, timeout=30
            )
            if resp.status_code in (200, 201):
                qb_result = resp.json().get("Item", {})
                item.qb_item_id = qb_result.get("Id")
                db.commit()
                results.append({"name": item.name, "ok": True, "qb_id": item.qb_item_id})
            else:
                results.append({"name": item.name, "ok": False, "error": resp.text[:200]})
        except Exception as e:
            results.append({"name": item.name, "ok": False, "error": str(e)[:200]})
    ok_count = sum(1 for r in results if r["ok"])
    return {"total": len(results), "synced": ok_count, "failed": len(results) - ok_count, "details": results}



# =============================================================================
# SUPPLIER PORTAL SCRAPERS
# =============================================================================

from bs4 import BeautifulSoup
import re
from typing import Dict, Any
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
import os

class PortalScrapeResult(BaseModel):
    supplier_name: str
    orders_found: int
    new_orders: List[Dict[str, Any]]
    already_received: List[str]
    errors: List[str]


def get_firebase_auth_token() -> str:
    """Get Firebase auth token for API calls."""
    auth_resp = requests.post(
        f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}",
        json={
            "email": "moxley@oxleytireinc.com",
            "password": "Silver28!!",
            "returnSecureToken": True
        },
        timeout=30
    )
    if auth_resp.status_code != 200:
        raise Exception(f"Firebase auth failed: {auth_resp.text}")
    return auth_resp.json().get("idToken")


def get_firebase_movements(id_token: str) -> Dict[str, dict]:
    """Fetch all movements from Firestore and return as dict keyed by PO number."""
    movements_resp = requests.get(
        f"https://firestore.googleapis.com/v1/projects/{FIREBASE_PROJECT_ID}/databases/(default)/documents/movements",
        headers={"Authorization": f"Bearer {id_token}"},
        timeout=30
    )
    movements = {}
    if movements_resp.status_code == 200:
        docs = movements_resp.json().get("documents", [])
        for doc in docs:
            fields = doc.get("fields", {})
            po_number = fields.get("poNumber", {}).get("stringValue", "")
            if po_number:
                movements[po_number] = fields
    return movements


def create_firebase_movement(id_token: str, movement_data: dict) -> bool:
    """Create a new movement document in Firestore."""
    # Convert to Firestore format
    firestore_doc = {"fields": {}}
    for key, value in movement_data.items():
        if isinstance(value, str):
            firestore_doc["fields"][key] = {"stringValue": value}
        elif isinstance(value, int):
            firestore_doc["fields"][key] = {"integerValue": str(value)}
        elif isinstance(value, float):
            firestore_doc["fields"][key] = {"doubleValue": value}
        elif isinstance(value, bool):
            firestore_doc["fields"][key] = {"booleanValue": value}
        elif isinstance(value, list):
            # Convert list to Firestore array
            array_values = []
            for item in value:
                if isinstance(item, dict):
                    map_fields = {}
                    for k, v in item.items():
                        if isinstance(v, str):
                            map_fields[k] = {"stringValue": v}
                        elif isinstance(v, (int, float)):
                            map_fields[k] = {"doubleValue": float(v) if isinstance(v, float) else {"integerValue": str(v)}}
                    array_values.append({"mapValue": {"fields": map_fields}})
            firestore_doc["fields"][key] = {"arrayValue": {"values": array_values}}

    resp = requests.post(
        f"https://firestore.googleapis.com/v1/projects/{FIREBASE_PROJECT_ID}/databases/(default)/documents/movements",
        headers={"Authorization": f"Bearer {id_token}", "Content-Type": "application/json"},
        json=firestore_doc,
        timeout=30
    )
    return resp.status_code in (200, 201)


def scrape_mekaniq_portal(portal_url: str, username: str, password: str) -> Dict[str, Any]:
    """
    Scrape Mekaniq dealer portal for completed orders.
    Returns dict with orders list and any errors.
    """
    session = requests.Session()
    orders = []
    errors = []

    # Set user agent
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    })

    try:
        # Step 1: Get login page
        base_url = f"https://{portal_url}" if not portal_url.startswith('http') else portal_url
        login_url = f"{base_url}/dealer/login" if '/dealer' not in base_url else base_url

        login_page = session.get(login_url, timeout=30)
        if login_page.status_code != 200:
            errors.append(f"Could not access login page: HTTP {login_page.status_code}")
            return {"orders": orders, "errors": errors}

        # Parse login form to get CSRF token if present
        soup = BeautifulSoup(login_page.text, 'lxml')
        csrf_token = None
        csrf_input = soup.find('input', {'name': re.compile(r'csrf|_token', re.I)})
        if csrf_input:
            csrf_token = csrf_input.get('value', '')

        # Step 2: Submit login
        login_data = {
            'username': username,
            'password': password,
        }
        if csrf_token:
            login_data['_token'] = csrf_token

        login_resp = session.post(
            f"{base_url}/dealer/login",
            data=login_data,
            timeout=30,
            allow_redirects=True
        )

        # Check if login successful (look for dashboard or orders page)
        if 'login' in login_resp.url.lower() and 'dashboard' not in login_resp.url.lower():
            # Try alternate login endpoints
            alt_login_data = {
                'user': username,
                'pass': password,
            }
            if csrf_token:
                alt_login_data['_token'] = csrf_token

            login_resp = session.post(
                f"{base_url}/login",
                data=alt_login_data,
                timeout=30,
                allow_redirects=True
            )

        # Step 3: Navigate to order history
        order_history_urls = [
            f"{base_url}/dealer/orders",
            f"{base_url}/orders",
            f"{base_url}/dealer/order-history",
            f"{base_url}/order-history",
            f"{base_url}/account/orders",
        ]

        orders_page = None
        for url in order_history_urls:
            try:
                resp = session.get(url, timeout=30)
                if resp.status_code == 200 and ('order' in resp.text.lower() or 'invoice' in resp.text.lower()):
                    orders_page = resp
                    break
            except:
                continue

        if not orders_page:
            errors.append("Could not find order history page")
            return {"orders": orders, "errors": errors}

        # Step 4: Parse orders
        soup = BeautifulSoup(orders_page.text, 'lxml')

        # Look for order tables or order cards
        order_rows = soup.find_all('tr', class_=re.compile(r'order|invoice', re.I))
        if not order_rows:
            order_rows = soup.find_all('div', class_=re.compile(r'order|invoice', re.I))
        if not order_rows:
            # Try to find any table with order data
            tables = soup.find_all('table')
            for table in tables:
                rows = table.find_all('tr')[1:]  # Skip header
                for row in rows:
                    cells = row.find_all(['td', 'th'])
                    if len(cells) >= 3:
                        order_rows.append(row)

        for row in order_rows:
            try:
                order_data = parse_mekaniq_order_row(row, session, base_url)
                if order_data:
                    orders.append(order_data)
            except Exception as e:
                errors.append(f"Error parsing order row: {str(e)}")

    except requests.exceptions.RequestException as e:
        errors.append(f"Network error: {str(e)}")
    except Exception as e:
        errors.append(f"Scraping error: {str(e)}")

    return {"orders": orders, "errors": errors}


def parse_mekaniq_order_row(row, session, base_url) -> Optional[Dict[str, Any]]:
    """Parse a single order row from Mekaniq portal."""
    cells = row.find_all(['td', 'th'])
    if not cells:
        return None

    # Extract order number - look for PO# pattern like "PO#121425MO"
    text = row.get_text()
    po_match = re.search(r'(PO#?\s*\d+[A-Z]*|\d{6,}[A-Z]+)', text, re.I)
    order_number = po_match.group(1) if po_match else None

    if not order_number:
        # Try finding in links
        links = row.find_all('a')
        for link in links:
            href = link.get('href', '')
            if 'order' in href.lower() or 'invoice' in href.lower():
                order_number = link.get_text().strip()
                break

    if not order_number:
        return None

    # Clean order number
    order_number = re.sub(r'\s+', '', order_number)

    # Try to get order details page
    detail_link = row.find('a', href=re.compile(r'order|detail|view', re.I))
    line_items = []

    if detail_link:
        try:
            detail_url = detail_link.get('href')
            if not detail_url.startswith('http'):
                detail_url = f"{base_url}{detail_url}" if detail_url.startswith('/') else f"{base_url}/{detail_url}"

            detail_resp = session.get(detail_url, timeout=30)
            if detail_resp.status_code == 200:
                line_items = parse_mekaniq_order_details(detail_resp.text)
        except:
            pass

    # Extract date
    date_match = re.search(r'(\d{1,2}[-/]\d{1,2}[-/]\d{2,4})', text)
    order_date = date_match.group(1) if date_match else None

    # Extract status
    status = 'completed'
    if re.search(r'shipped|delivered|complete', text, re.I):
        status = 'shipped'
    elif re.search(r'pending|processing', text, re.I):
        status = 'pending'

    return {
        "order_number": order_number,
        "date": order_date,
        "status": status,
        "line_items": line_items,
        "supplier": "Mekaniq"
    }


def parse_mekaniq_order_details(html: str) -> List[Dict[str, Any]]:
    """Parse order details page to extract line items."""
    soup = BeautifulSoup(html, 'lxml')
    items = []

    # Look for items table
    tables = soup.find_all('table')
    for table in tables:
        rows = table.find_all('tr')
        headers = []

        # Get headers
        header_row = table.find('tr')
        if header_row:
            headers = [th.get_text().strip().lower() for th in header_row.find_all(['th', 'td'])]

        # Parse data rows
        for row in rows[1:]:
            cells = row.find_all(['td', 'th'])
            if len(cells) < 3:
                continue

            item = {}
            cell_texts = [c.get_text().strip() for c in cells]

            # Try to map to known fields
            for i, text in enumerate(cell_texts):
                if i < len(headers):
                    header = headers[i]
                    if 'code' in header or 'sku' in header or 'item' in header:
                        item['item_code'] = text
                    elif 'brand' in header:
                        item['brand'] = text
                    elif 'size' in header:
                        item['size'] = text
                    elif 'pattern' in header or 'model' in header:
                        item['pattern'] = text
                    elif 'qty' in header or 'quantity' in header:
                        item['quantity'] = int(re.sub(r'[^\d]', '', text) or 0)
                    elif 'price' in header or 'cost' in header:
                        price_match = re.search(r'[\d,]+\.?\d*', text)
                        if price_match:
                            item['unit_price'] = float(price_match.group().replace(',', ''))
                    elif 'fet' in header.lower():
                        fet_match = re.search(r'[\d,]+\.?\d*', text)
                        if fet_match:
                            item['fet'] = float(fet_match.group().replace(',', ''))

            # If no headers, try positional parsing
            if not item.get('item_code') and len(cell_texts) >= 3:
                item['item_code'] = cell_texts[0]
                if len(cell_texts) >= 4:
                    item['description'] = cell_texts[1]
                    qty_match = re.search(r'\d+', cell_texts[2])
                    if qty_match:
                        item['quantity'] = int(qty_match.group())
                    price_match = re.search(r'[\d,]+\.?\d*', cell_texts[3])
                    if price_match:
                        item['unit_price'] = float(price_match.group().replace(',', ''))

            if item.get('item_code'):
                items.append(item)

    return items


def scrape_atd_portal(portal_url: str, username: str, password: str) -> Dict[str, Any]:
    """Scrape ATD dealer portal."""
    session = requests.Session()
    orders = []
    errors = []

    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })

    try:
        base_url = f"https://{portal_url}" if not portal_url.startswith('http') else portal_url

        # ATD typically uses atd.com or atdonline.com
        login_url = f"{base_url}/login"
        login_page = session.get(login_url, timeout=30)

        soup = BeautifulSoup(login_page.text, 'lxml')
        csrf_token = None
        csrf_input = soup.find('input', {'name': re.compile(r'csrf|token', re.I)})
        if csrf_input:
            csrf_token = csrf_input.get('value')

        login_data = {'username': username, 'password': password}
        if csrf_token:
            login_data['_token'] = csrf_token

        login_resp = session.post(login_url, data=login_data, timeout=30, allow_redirects=True)

        # Navigate to order history
        for orders_url in [f"{base_url}/orders", f"{base_url}/order-history", f"{base_url}/account/orders"]:
            try:
                resp = session.get(orders_url, timeout=30)
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, 'lxml')
                    order_elements = soup.find_all(['tr', 'div'], class_=re.compile(r'order', re.I))

                    for elem in order_elements:
                        text = elem.get_text()
                        po_match = re.search(r'(PO[-#]?\s*\d+|\d{8,})', text)
                        if po_match:
                            orders.append({
                                "order_number": po_match.group(1),
                                "status": "shipped" if 'ship' in text.lower() else "pending",
                                "supplier": "ATD",
                                "line_items": []
                            })
                    break
            except:
                continue

    except Exception as e:
        errors.append(f"ATD scraping error: {str(e)}")

    return {"orders": orders, "errors": errors}


def scrape_km_tire_portal(portal_url: str, username: str, password: str) -> Dict[str, Any]:
    """Scrape K&M Tire dealer portal."""
    session = requests.Session()
    orders = []
    errors = []

    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })

    try:
        base_url = f"https://{portal_url}" if not portal_url.startswith('http') else portal_url

        # K&M Tire login
        login_url = f"{base_url}/login"
        login_page = session.get(login_url, timeout=30)

        soup = BeautifulSoup(login_page.text, 'lxml')
        csrf_token = None
        csrf_input = soup.find('input', {'name': re.compile(r'csrf|token', re.I)})
        if csrf_token:
            csrf_token = csrf_input.get('value')

        login_data = {'email': username, 'password': password}
        if csrf_token:
            login_data['_token'] = csrf_token

        login_resp = session.post(login_url, data=login_data, timeout=30, allow_redirects=True)

        # Navigate to orders
        for orders_url in [f"{base_url}/account/orders", f"{base_url}/orders", f"{base_url}/order-history"]:
            try:
                resp = session.get(orders_url, timeout=30)
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, 'lxml')
                    order_elements = soup.find_all(['tr', 'div'], class_=re.compile(r'order', re.I))

                    for elem in order_elements:
                        text = elem.get_text()
                        po_match = re.search(r'(PO[-#]?\s*\d+|\d{6,})', text)
                        if po_match:
                            orders.append({
                                "order_number": po_match.group(1),
                                "status": "shipped" if 'ship' in text.lower() else "pending",
                                "supplier": "K&M Tire",
                                "line_items": []
                            })
                    break
            except:
                continue

    except Exception as e:
        errors.append(f"K&M Tire scraping error: {str(e)}")

    return {"orders": orders, "errors": errors}


def scrape_hesselbein_portal(portal_url: str, username: str, password: str, screenshot_path: str = None) -> Dict[str, Any]:
    """Scrape Hesselbein (DKTire) portal. Playwright login + direct API calls."""
    orders = []
    errors = []
    login_success = False
    api_base = "https://api-b2b.dktire.com"
    access_token = None
    token_type = None

    # Step 1: Playwright login to get auth token
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"])
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
            page = context.new_page()
            page.goto("https://b2b.dktire.com/auth-signin", timeout=60000)
            page.wait_for_load_state("networkidle", timeout=30000)

            import time as _time
            _time.sleep(3)

            # Fill username
            for sel in ['input[type="text"]', 'input[name="username"]', 'input[name="account"]']:
                try:
                    loc = page.locator(sel).first
                    if loc.is_visible(timeout=2000):
                        loc.fill(username)
                        break
                except:
                    continue

            # Fill password
            for sel in ['input[type="password"]', 'input[name="password"]']:
                try:
                    loc = page.locator(sel).first
                    if loc.is_visible(timeout=2000):
                        loc.fill(password)
                        break
                except:
                    continue

            # Click submit
            for sel in ['button[type="submit"]', 'button:has-text("Sign In")', 'button:has-text("Login")', '.btn-primary']:
                try:
                    loc = page.locator(sel).first
                    if loc.is_visible(timeout=2000):
                        loc.click()
                        break
                except:
                    continue

            _time.sleep(5)
            page.wait_for_load_state("networkidle", timeout=30000)

            # Extract token from localStorage
            try:
                auth_json = page.evaluate("() => localStorage.getItem('authUser')")
                if auth_json:
                    import json as _json
                    auth_data = _json.loads(auth_json)
                    access_token = auth_data.get("access_token")
                    token_type = auth_data.get("token_type", "Bearer")
                    if access_token:
                        login_success = True
            except Exception as e:
                errors.append(f"Token extraction: {str(e)}")

            if screenshot_path:
                try:
                    page.screenshot(path=screenshot_path, full_page=True)
                except:
                    pass

            browser.close()

    except Exception as e:
        errors.append(f"Playwright error: {str(e)}")

    if not access_token:
        errors.append("Could not get auth token")
        return {"orders": orders, "errors": errors, "login_success": login_success}

    # Step 2: Direct API calls with the token
    api_headers = {
        "Authorization": f"{token_type} {access_token}",
        "Content-Type": "application/json",
        "Timezone": "America/Chicago"
    }

    try:
        # Get user details for ship_to UUID
        user_resp = requests.get(f"{api_base}/master/user-details", headers=api_headers, timeout=30)
        ship_to_uuid = ""
        if user_resp.status_code == 200:
            ud = user_resp.json()
            ship_to_list = ud.get("ship_to", [])
            if isinstance(ship_to_list, list) and ship_to_list:
                ship_to_uuid = ship_to_list[0].get("value", "") if isinstance(ship_to_list[0], dict) else str(ship_to_list[0])

        if not ship_to_uuid:
            ship_to_uuid = "83373a2b-d442-41e6-8d65-531240a0ecb4"

        # Get site list for this ship_to
        site_resp = requests.get(f"{api_base}/order/get-site-list-by-shipto", headers=api_headers, params={"ship_to": ship_to_uuid}, timeout=30)
        site_id = ""
        if site_resp.status_code == 200:
            sites = site_resp.json()
            if isinstance(sites, list) and sites:
                site_id = sites[0].get("value", sites[0].get("id", "")) if isinstance(sites[0], dict) else str(sites[0])

        # Try invoice list with ship_from = ship_to UUID (common pattern)
        ship_from_options = [ship_to_uuid]
        if site_id:
            ship_from_options.insert(0, site_id)

        invoice_data = None
        for sf in ship_from_options:
            inv_resp = requests.get(
                f"{api_base}/order/get-invoice-list",
                headers=api_headers,
                params={"ship_from": sf, "from_date": "2025-01-01", "to_date": "2026-12-31"},
                timeout=30
            )
            if inv_resp.status_code == 200:
                invoice_data = inv_resp.json()
                break
            errors.append(f"Invoices ship_from={sf}: {inv_resp.status_code} {inv_resp.text[:200]}")

        # Try open orders too
        if not invoice_data:
            for sf in ship_from_options:
                oo_resp = requests.get(
                    f"{api_base}/order/get-open-orders-list",
                    headers=api_headers,
                    params={"ship_from": sf, "from_date": "2025-01-01", "to_date": "2026-12-31"},
                    timeout=30
                )
                if oo_resp.status_code == 200:
                    invoice_data = oo_resp.json()
                    break

        # Try order history
        if not invoice_data:
            for sf in ship_from_options:
                oh_resp = requests.get(
                    f"{api_base}/order/get-order-history-by-date",
                    headers=api_headers,
                    params={"ship_from": sf, "from_date": "2025-01-01", "to_date": "2026-12-31"},
                    timeout=30
                )
                if oh_resp.status_code == 200:
                    invoice_data = oh_resp.json()
                    break
                errors.append(f"History ship_from={sf}: {oh_resp.status_code} {oh_resp.text[:200]}")

        # Try open invoices
        if not invoice_data:
            for sf in ship_from_options:
                oi_resp = requests.get(
                    f"{api_base}/order/get-open-invoice-list",
                    headers=api_headers,
                    params={"ship_from": sf, "from_date": "2025-01-01", "to_date": "2026-12-31"},
                    timeout=30
                )
                if oi_resp.status_code == 200:
                    invoice_data = oi_resp.json()
                    break

        # Try using open orders with program variant
        if not invoice_data:
            for sf in ship_from_options:
                pgm_resp = requests.get(
                    f"{api_base}/order/get-open-orders-list-pgm",
                    headers=api_headers,
                    params={"ship_from": sf, "from_date": "2025-01-01", "to_date": "2026-12-31"},
                    timeout=30
                )
                if pgm_resp.status_code == 200:
                    invoice_data = pgm_resp.json()
                    break

        # Parse whatever data we got
        if invoice_data:
            if isinstance(invoice_data, dict):
                inv_list = invoice_data.get("data", invoice_data.get("invoices", invoice_data.get("orders", invoice_data.get("results", []))))
                if not isinstance(inv_list, list):
                    inv_list = [invoice_data] if invoice_data else []
            elif isinstance(invoice_data, list):
                inv_list = invoice_data
            else:
                inv_list = []

            for inv in inv_list:
                if not isinstance(inv, dict):
                    continue
                order_num = str(inv.get("invoice_id", inv.get("invoice_number", inv.get("order_number", inv.get("sales_id", inv.get("id", ""))))))
                if not order_num or order_num == "None":
                    continue
                # Skip returns unless negative qty tracking needed later
                order_type = inv.get("order_type", "")
                line_items = []
                items_data = inv.get("line_items", inv.get("items", inv.get("details", inv.get("order_lines", []))))
                if isinstance(items_data, list):
                    for item in items_data:
                        if isinstance(item, dict):
                            line_items.append({
                                "sku": item.get("item_id", item.get("sku", item.get("item_code", item.get("part_number", "")))),
                                "size": item.get("size_description", item.get("size", item.get("tire_size", ""))),
                                "description": item.get("item_description", item.get("description", item.get("name", ""))),
                                "quantity": str(item.get("qty", item.get("quantity", item.get("ordered_qty", 0)))),
                                "unit_price": str(item.get("unit_price", item.get("net_price", item.get("price", 0)))),
                                "fet": str(item.get("fet_amount", item.get("fet", item.get("excise_tax", 0)))),
                                "total": str(item.get("line_total", item.get("total", item.get("amount", 0))))
                            })
                orders.append({
                    "order_number": order_num,
                    "date": inv.get("invoice_date", inv.get("date", inv.get("order_date", ""))),
                    "type": order_type,
                    "total": inv.get("order_total", 0),
                    "customer_po": inv.get("customer_po", ""),
                    "status": "completed",
                    "supplier": "Hesselbein Tire",
                    "line_items": line_items
                })
            # Debug: show raw data structure
            if inv_list:
                import json as _json
                for sample in inv_list[:2]:
                    if isinstance(sample, dict):
                        errors.append(f"Sample keys: {list(sample.keys())}")
                        errors.append(f"Sample: {str(sample)[:500]}")
            errors.append(f"Parsed {len(inv_list)} records from API")
        else:
            errors.append("No invoice data returned from any API endpoint")

    except Exception as e:
        errors.append(f"API error: {str(e)}")

    return {"orders": orders, "errors": errors, "login_success": login_success}


def scrape_south_gateway_portal(portal_url: str, username: str, password: str) -> Dict[str, Any]:
    """Scrape South Gateway dealer portal."""
    session = requests.Session()
    orders = []
    errors = []

    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })

    try:
        # South Gateway dealer portal
        base_url = "https://dealer.southgatewaytire.com"

        login_page = session.get(f"{base_url}/login", timeout=30)

        login_data = {'customer_id': username, 'password': password}
        login_resp = session.post(f"{base_url}/login", data=login_data, timeout=30, allow_redirects=True)

        orders_resp = session.get(f"{base_url}/orders", timeout=30)
        if orders_resp.status_code == 200:
            soup = BeautifulSoup(orders_resp.text, 'lxml')
            for row in soup.find_all(['tr', 'div'], class_=re.compile(r'order|invoice', re.I)):
                text = row.get_text()
                po_match = re.search(r'(\d{6,})', text)
                if po_match:
                    orders.append({
                        "order_number": po_match.group(1),
                        "status": "shipped" if 'ship' in text.lower() else "pending",
                        "supplier": "South Gateway",
                        "line_items": []
                    })

    except Exception as e:
        errors.append(f"South Gateway scraping error: {str(e)}")

    return {"orders": orders, "errors": errors}


def scrape_bzo_portal(portal_url: str, username: str, password: str, screenshot_path: str = None) -> Dict[str, Any]:
    """Scrape BZO Wheels/TireLink portal using plain requests (TireGuru backend)."""
    orders = []
    errors = []
    login_success = False

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    })

    try:
        # Step 1: GET bzowheelandtire.com to extract hidden fields
        login_page = session.get("https://bzowheelandtire.com", timeout=30)
        soup = BeautifulSoup(login_page.text, 'lxml')

        server_field = soup.find('input', {'name': 'server'})
        from_field = soup.find('input', {'name': 'from'})

        server_value = server_field.get('value', '') if server_field else ''
        from_value = from_field.get('value', '') if from_field else ''

        if not server_value:
            errors.append("Could not extract server field from BZO login page")
            return {"orders": orders, "errors": errors, "login_success": False}

        # Step 2: POST to TireGuru checkLogin.php
        login_data = {
            'server': server_value,
            'from': from_value,
            'username': username,
            'password': password
        }

        login_resp = session.post(
            "https://companylinkhere.tireguru.net/checkLogin.php",
            data=login_data,
            timeout=30,
            allow_redirects=True
        )

        # Check login success - should redirect to dashboard or not show login error
        if login_resp.status_code == 200 and 'invalid' not in login_resp.text.lower() and 'error' not in login_resp.text.lower():
            login_success = True

        if not login_success:
            errors.append("BZO login failed - invalid credentials or server error")
            return {"orders": orders, "errors": errors, "login_success": False}

        # Step 3: GET /reports/complete to get order list
        orders_resp = session.get(
            "https://companylinkhere.tireguru.net/reports/complete",
            timeout=30
        )

        if orders_resp.status_code != 200:
            errors.append(f"Failed to fetch orders page: {orders_resp.status_code}")
            return {"orders": orders, "errors": errors, "login_success": login_success}

        orders_soup = BeautifulSoup(orders_resp.text, 'lxml')

        # Parse orders table - each tr has data-index and cells: order#, blank, date, type, qty, total
        for row in orders_soup.find_all('tr', attrs={'data-index': True}):
            data_index = row.get('data-index')
            cells = row.find_all('td')

            if len(cells) >= 6:
                order_number = cells[0].get_text(strip=True)
                order_date = cells[2].get_text(strip=True)
                order_type = cells[3].get_text(strip=True)
                qty = cells[4].get_text(strip=True)
                total = cells[5].get_text(strip=True)

                # Step 4: GET order details for line items
                line_items = []
                try:
                    details_resp = session.get(
                        f"https://companylinkhere.tireguru.net/reports/complete/{data_index}/details",
                        timeout=30
                    )

                    if details_resp.status_code == 200:
                        details_soup = BeautifulSoup(details_resp.text, 'lxml')

                        # Parse line items: SKU, size, description (brand+model), qty, unit price, FET blank, FET, total
                        for item_row in details_soup.find_all('tr'):
                            item_cells = item_row.find_all('td')
                            if len(item_cells) >= 8:
                                sku = item_cells[0].get_text(strip=True)
                                size = item_cells[1].get_text(strip=True)
                                description = item_cells[2].get_text(strip=True)
                                item_qty = item_cells[3].get_text(strip=True)
                                unit_price = item_cells[4].get_text(strip=True)
                                fet = item_cells[6].get_text(strip=True)
                                item_total = item_cells[7].get_text(strip=True)

                                if sku:  # Skip header rows
                                    line_items.append({
                                        "sku": sku,
                                        "size": size,
                                        "description": description,
                                        "quantity": item_qty,
                                        "unit_price": unit_price,
                                        "fet": fet,
                                        "total": item_total
                                    })
                except Exception as e:
                    errors.append(f"Error fetching details for order {order_number}: {str(e)}")

                orders.append({
                    "order_number": order_number,
                    "date": order_date,
                    "type": order_type,
                    "quantity": qty,
                    "total": total,
                    "status": "completed",
                    "supplier": "BZO Wheels/TireLink",
                    "line_items": line_items
                })

    except Exception as e:
        errors.append(f"BZO scraping error: {str(e)}")

    return {"orders": orders, "errors": errors, "login_success": login_success}


# Mapping of supplier names to scraper functions
PORTAL_SCRAPERS = {
    "Mekaniq": scrape_mekaniq_portal,
    "ATD": scrape_atd_portal,
    "K&M Tire": scrape_km_tire_portal,
    "Hesselbein Tire": scrape_hesselbein_portal,
    "South Gateway": scrape_south_gateway_portal,
    "BZO Wheels/TireLink (Royal Black)": scrape_bzo_portal,
}


class PortalLoginTestResult(BaseModel):
    portal: str
    login_success: bool
    screenshot_path: Optional[str] = None
    errors: List[str]


@app.post("/suppliers/test-portal-login")
def test_portal_login(
    portal: str,
    username: str,
    password: str,
    current_user: User = Depends(get_current_user)
):
    """
    Test login to a supplier portal (BZO/TireLink or Hesselbein).
    Takes a screenshot of the order history page if login succeeds.
    """
    screenshot_dir = os.path.join(os.path.dirname(__file__), "static", "screenshots")
    os.makedirs(screenshot_dir, exist_ok=True)

    portal_lower = portal.lower()

    if "bzo" in portal_lower or "tirelink" in portal_lower:
        screenshot_path = os.path.join(screenshot_dir, f"bzo_orders_{current_user.id}.png")
        result = scrape_bzo_portal("", username, password, screenshot_path=screenshot_path)
        return PortalLoginTestResult(
            portal="BZO Wheels/TireLink",
            login_success=result.get("login_success", False),
            screenshot_path=f"/static/screenshots/bzo_orders_{current_user.id}.png" if result.get("login_success") else None,
            errors=result.get("errors", [])
        )
    elif "hesselbein" in portal_lower:
        screenshot_path = os.path.join(screenshot_dir, f"hesselbein_orders_{current_user.id}.png")
        result = scrape_hesselbein_portal("", username, password, screenshot_path=screenshot_path)
        return PortalLoginTestResult(
            portal="Hesselbein Tire",
            login_success=result.get("login_success", False),
            screenshot_path=f"/static/screenshots/hesselbein_orders_{current_user.id}.png" if result.get("login_success") else None,
            errors=result.get("errors", [])
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unknown portal: {portal}. Supported: BZO, TireLink, Hesselbein")


@app.post("/suppliers/check-portals", response_model=List[PortalScrapeResult])
def check_supplier_portals(
    supplier_ids: Optional[List[int]] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Scan supplier portals for new orders and auto-receive into Firebase.
    If supplier_ids is None, checks all active suppliers with portal credentials.
    """
    results = []

    # Get Firebase auth token and existing movements
    try:
        firebase_token = get_firebase_auth_token()
        existing_movements = get_firebase_movements(firebase_token)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Firebase connection failed: {str(e)}")

    # Get suppliers to check
    query = db.query(Supplier).filter(
        Supplier.owner_id == current_user.id,
        Supplier.is_active == True,
        Supplier.portal_username != None,
        Supplier.portal_password_encrypted != None
    )

    if supplier_ids:
        query = query.filter(Supplier.id.in_(supplier_ids))

    suppliers = query.all()

    for supplier in suppliers:
        result = PortalScrapeResult(
            supplier_name=supplier.name,
            orders_found=0,
            new_orders=[],
            already_received=[],
            errors=[]
        )

        # Get the appropriate scraper
        scraper_func = None
        for scraper_name, func in PORTAL_SCRAPERS.items():
            if scraper_name.lower() in supplier.name.lower():
                scraper_func = func
                break

        if not scraper_func:
            result.errors.append(f"No scraper available for supplier: {supplier.name}")
            results.append(result)
            continue

        # Decrypt password
        try:
            password = _simple_decrypt(supplier.portal_password_encrypted)
        except:
            result.errors.append("Could not decrypt portal password")
            results.append(result)
            continue

        # Scrape the portal
        portal_url = supplier.portal_url or supplier.website or f"{supplier.name.lower().replace(' ', '')}.com"
        scrape_result = scraper_func(portal_url, supplier.portal_username, password)

        result.orders_found = len(scrape_result.get("orders", []))
        result.errors.extend(scrape_result.get("errors", []))

        # Process each order
        for order in scrape_result.get("orders", []):
            order_number = order.get("order_number", "")

            # Check if already received in Firebase
            if order_number in existing_movements:
                result.already_received.append(order_number)
                continue

            # Create receive movement in Firebase
            movement_data = {
                "poNumber": order_number,
                "supplier": supplier.name,
                "type": "receive",
                "status": "completed",
                "date": order.get("date") or dt.datetime.now().isoformat(),
                "items": order.get("line_items", []),
                "createdAt": dt.datetime.now().isoformat(),
                "autoReceived": True
            }

            try:
                if create_firebase_movement(firebase_token, movement_data):
                    result.new_orders.append({
                        "order_number": order_number,
                        "items_count": len(order.get("line_items", [])),
                        "status": "auto-received"
                    })
                else:
                    result.errors.append(f"Failed to create movement for {order_number}")
            except Exception as e:
                result.errors.append(f"Error creating movement for {order_number}: {str(e)}")

        results.append(result)

    return results


@app.get("/suppliers/{supplier_id}/check-portal")
def check_single_supplier_portal(
    supplier_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Check a single supplier's portal for new orders."""
    results = check_supplier_portals(
        supplier_ids=[supplier_id],
        db=db,
        current_user=current_user
    )
    if results:
        return results[0]
    raise HTTPException(status_code=404, detail="Supplier not found")


# =============================================================================
# ORDERS HISTORY - Firebase movements
# =============================================================================

def _parse_firestore_val(v, default=None):
    """Parse a single Firestore typed value."""
    if not isinstance(v, dict):
        return default
    if "stringValue" in v:
        return v["stringValue"]
    if "integerValue" in v:
        return int(v["integerValue"])
    if "doubleValue" in v:
        return float(v["doubleValue"])
    if "booleanValue" in v:
        return v["booleanValue"]
    return default


def _parse_firestore_map_items(fields: dict) -> list:
    """Parse line items from a Firestore document's arrayValue field."""
    items_field = fields.get("items", {})
    line_items = []
    if "arrayValue" in items_field:
        for item_val in items_field["arrayValue"].get("values", []):
            if "mapValue" in item_val:
                f = item_val["mapValue"]["fields"]
                line_items.append({
                    "sku": _parse_firestore_val(f.get("sku"), ""),
                    "size": _parse_firestore_val(f.get("size"), ""),
                    "description": _parse_firestore_val(f.get("description"), ""),
                    "quantity": _parse_firestore_val(f.get("quantity"), ""),
                    "unit_price": _parse_firestore_val(f.get("unit_price"), ""),
                    "fet": _parse_firestore_val(f.get("fet"), ""),
                    "total": _parse_firestore_val(f.get("total"), ""),
                })
    return line_items


@app.get("/movements/history")
def get_firebase_order_history(
    supplier: Optional[str] = Query(None),
    order_type: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user)
):
    """Get order history from Firebase movements. Groups individual tire movements by order#."""
    try:
        firebase_token = get_firebase_auth_token()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Firebase auth failed: {str(e)}")

    try:
        resp = requests.get(
            f"https://firestore.googleapis.com/v1/projects/{FIREBASE_PROJECT_ID}/databases/(default)/documents/movements",
            headers={"Authorization": f"Bearer {firebase_token}"},
            params={"pageSize": 1000},
            timeout=30
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Firestore fetch failed: {str(e)}")

    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Firestore error: {resp.text[:200]}")

    docs = resp.json().get("documents", [])

    # Each doc is a single tire movement; group by extracted order number
    # Actual fields: brand, model, size, qty, source, notes, zone, condition, position, sku, userId, userEmail
    # notes example: "Auto-received from BZO Wheels/TireLink (Royal Black) #24678"
    orders: dict = {}

    for doc in docs:
        fields = doc.get("fields", {})
        notes    = _parse_firestore_val(fields.get("notes"), "")
        source   = _parse_firestore_val(fields.get("source"), "receive")
        brand    = _parse_firestore_val(fields.get("brand"), "")
        model    = _parse_firestore_val(fields.get("model"), "")
        size     = _parse_firestore_val(fields.get("size"), "")
        qty      = _parse_firestore_val(fields.get("qty"), "")
        sku      = _parse_firestore_val(fields.get("sku"), "")
        condition= _parse_firestore_val(fields.get("condition"), "")
        position = _parse_firestore_val(fields.get("position"), "")
        # Prefer the order date stored in the document; fall back to Firestore createTime
        stored_date = _parse_firestore_val(fields.get("date"), "")
        if stored_date:
            doc_date = stored_date[:10]
        else:
            doc_date = doc.get("createTime", doc.get("updateTime", ""))[:10] if doc.get("createTime") else ""

        # Extract order number from notes: #NNNNNN or 90-NNNNNN (Hesselbein)
        order_num = ""
        hess_match = re.search(r'(90-\d+)', notes)
        bzo_match  = re.search(r'#(\d{4,6})', notes)
        if hess_match:
            order_num = hess_match.group(1)
        elif bzo_match:
            order_num = bzo_match.group(1)
        else:
            # Use last path segment of document name as fallback key
            order_num = doc.get("name", "").split("/")[-1]

        # Extract supplier from notes
        supplier_name = "Unknown"
        notes_lower = notes.lower()
        if "bzo" in notes_lower or "tirelink" in notes_lower or "royal black" in notes_lower:
            supplier_name = "BZO"
        elif "hesselbein" in notes_lower or "dktire" in notes_lower:
            supplier_name = "Hesselbein"
        elif notes:
            # Try to pull from "from X #" pattern
            m = re.search(r'from (.+?) #', notes)
            if m:
                supplier_name = m.group(1).strip()

        # Apply filters
        if supplier and supplier.lower() not in supplier_name.lower():
            continue
        if order_type and order_type.lower() not in source.lower():
            continue

        line_item = {
            "sku": sku,
            "brand": brand,
            "model": model,
            "size": size,
            "condition": condition,
            "position": position,
            "quantity": str(qty),
            "description": f"{brand} {model} {size}".strip(),
        }

        if order_num not in orders:
            orders[order_num] = {
                "po_number": order_num,
                "supplier": supplier_name,
                "type": source,
                "date": doc_date,
                "notes": notes,
                "items_count": 0,
                "line_items": [],
            }

        orders[order_num]["line_items"].append(line_item)
        orders[order_num]["items_count"] += 1
        # Keep earliest date as the order date
        if doc_date and (not orders[order_num]["date"] or doc_date < orders[order_num]["date"]):
            orders[order_num]["date"] = doc_date

    result = sorted(orders.values(), key=lambda x: x.get("date", ""), reverse=True)
    return {"orders": result, "total": len(result)}


# =============================================================================
# HESSELBEIN AUTO-RECEIVE
# =============================================================================

@app.post("/suppliers/hesselbein/auto-receive")
def hesselbein_auto_receive(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Auto-receive all Hesselbein orders into Firebase that aren't already there."""
    supplier = db.query(Supplier).filter(
        Supplier.owner_id == current_user.id,
        Supplier.name.ilike("%hesselbein%")
    ).first()

    if not supplier:
        raise HTTPException(status_code=404, detail="Hesselbein supplier not found. Add it in suppliers.")

    if not supplier.portal_username or not supplier.portal_password_encrypted:
        raise HTTPException(status_code=400, detail="Hesselbein portal credentials not set.")

    try:
        password = _simple_decrypt(supplier.portal_password_encrypted)
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decrypt Hesselbein portal password.")

    try:
        firebase_token = get_firebase_auth_token()
        existing_movements = get_firebase_movements(firebase_token)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Firebase auth failed: {str(e)}")

    scrape_result = scrape_hesselbein_portal("", supplier.portal_username, password)
    orders = scrape_result.get("orders", [])
    errors = scrape_result.get("errors", [])

    new_count = 0
    already_count = 0
    failed = []

    for order in orders:
        order_number = order.get("order_number", "")
        if not order_number:
            continue
        if order_number in existing_movements:
            already_count += 1
            continue

        movement_data = {
            "poNumber": order_number,
            "supplier": "Hesselbein Tire",
            "type": "receive",
            "status": "completed",
            "date": order.get("date") or dt.datetime.now().isoformat(),
            "total": str(order.get("total", "")),
            "customerPo": order.get("customer_po", ""),
            "orderType": order.get("type", ""),
            "items": order.get("line_items", []),
            "createdAt": dt.datetime.now().isoformat(),
            "autoReceived": True,
        }

        try:
            ok = create_firebase_movement(firebase_token, movement_data)
            if ok:
                new_count += 1
            else:
                failed.append(order_number)
        except Exception as e:
            failed.append(f"{order_number}: {str(e)[:50]}")

    return {
        "orders_found": len(orders),
        "new_received": new_count,
        "already_received": already_count,
        "failed": len(failed),
        "failed_list": failed[:20],
        "scrape_errors": errors[:10],
        "login_success": scrape_result.get("login_success", False),
    }


# =============================================================================
# SUPPLIER CATALOG — scraping helpers, upsert, cron, refresh endpoint
# =============================================================================

def _scrape_bzo_catalog(supplier: Supplier, password: str, search: Optional[str] = None) -> list:
    """Login to BZO TireGuru portal and return full tire catalog.

    Uses POST /lookup (not GET /lookup/tires?search) — the correct TireGuru
    approach: get CSRF token from /lookup/tires, then POST for each size.
    Refreshes the CSRF token from each response before the next POST.
    """
    import re as _re
    # TBR (truck/bus radial) sizes
    BZO_TBR_SIZES = [
        "11R22.5", "11R24.5", "295/75R22.5", "315/80R22.5",
        "255/70R22.5", "285/75R24.5", "385/65R22.5", "425/65R22.5",
        "235/85R16", "235/80R16", "225/75R15", "215/75R17.5",
        "235/75R17.5", "445/65R22.5",
    ]
    # PCR (passenger car replacement) sizes — high-volume sizes stocked by most dealers
    BZO_PCR_SIZES = [
        "185/65R15", "195/65R15", "205/65R15", "215/60R15", "225/60R15",
        "205/55R16", "215/55R16", "225/50R16", "215/60R16", "225/60R16",
        "235/60R16", "205/50R17", "215/45R17", "215/50R17", "225/45R17",
        "225/50R17", "225/55R17", "235/45R17", "235/55R17", "245/45R17",
        "245/65R17", "265/65R17", "265/70R17", "275/55R17", "225/40R18",
        "225/45R18", "235/40R18", "235/45R18", "245/40R18", "245/45R18",
        "255/45R18", "265/60R18", "265/65R18", "275/65R18", "285/60R18",
        "225/45R19", "235/35R19", "245/40R19", "255/35R19", "255/40R19",
        "245/35R20", "255/35R20", "265/50R20", "275/55R20", "285/50R20",
        "275/60R20", "265/70R16", "235/70R16", "245/70R16", "255/70R16",
    ]
    BZO_ALL_SIZES = BZO_TBR_SIZES + BZO_PCR_SIZES

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    })

    # Step 1: Login
    login_page = session.get("https://bzowheelandtire.com", timeout=30)
    soup = BeautifulSoup(login_page.text, 'lxml')
    server_field = soup.find('input', {'name': 'server'})
    from_field = soup.find('input', {'name': 'from'})
    server_value = server_field.get('value', '') if server_field else ''
    from_value = from_field.get('value', '') if from_field else ''
    if not server_value:
        raise ValueError("Could not extract BZO server field from login page.")
    login_resp = session.post(
        "https://companylinkhere.tireguru.net/checkLogin.php",
        data={'server': server_value, 'from': from_value,
              'username': supplier.portal_username, 'password': password},
        timeout=30, allow_redirects=True
    )
    if 'invalid' in login_resp.text.lower() or login_resp.status_code >= 400:
        raise ValueError("BZO login failed — invalid credentials.")

    # Step 2: Get initial CSRF token from /lookup/tires
    token_resp = session.get("https://companylinkhere.tireguru.net/lookup/tires", timeout=30)
    token_soup = BeautifulSoup(token_resp.text, 'lxml')
    token_input = token_soup.find('input', {'name': '_token'})
    current_token = token_input.get('value', '') if token_input else ''
    if not current_token:
        raise ValueError("Could not extract CSRF token from BZO /lookup/tires.")

    # Step 3: POST /lookup for each size, chaining CSRF tokens
    sizes_to_search = [search] if search else BZO_ALL_SIZES
    all_tires = []
    seen: set = set()  # deduplicate by (brand, description, size)

    for size in sizes_to_search:
        resp = session.post(
            "https://companylinkhere.tireguru.net/lookup",
            data={
                '_token': current_token,
                'type': 'tires',
                'raw': size,
                'wildcard': size,
                'mq_show': '0',
                'min_qty': '0',
                'prod_code': '',
                'desc': '',
            },
            timeout=30,
        )
        if resp.status_code != 200:
            continue

        result_soup = BeautifulSoup(resp.text, 'lxml')

        # Refresh CSRF token for next request
        next_token = result_soup.find('input', {'name': '_token'})
        if next_token:
            current_token = next_token.get('value', current_token)

        # Parse rows: cells [size, description, brand, <empty>, availability, cost_string, FET]
        for row in result_soup.find_all('tr'):
            cells = row.find_all('td')
            if len(cells) < 5:
                continue
            row_size    = cells[0].get_text(strip=True)
            description = cells[1].get_text(strip=True)
            brand       = cells[2].get_text(strip=True)
            availability= cells[4].get_text(strip=True) if len(cells) > 4 else ""
            cost_raw    = cells[5].get_text(strip=True) if len(cells) > 5 else ""
            fet_raw     = cells[6].get_text(strip=True) if len(cells) > 6 else ""

            # Cost cell contains "Cost[$29.39]" — extract the number
            cost_match = _re.search(r'Cost\[\$?([\d.]+)\]', cost_raw)
            cost = cost_match.group(1) if cost_match else cost_raw.lstrip('$').strip()

            fet = fet_raw.lstrip('$').strip()

            if not row_size and not description:
                continue

            key = (brand.lower(), description.lower(), (row_size or size).lower())
            if key in seen:
                continue
            seen.add(key)

            all_tires.append({
                "sku": "",
                "size": row_size or size,
                "description": description,
                "brand": brand,
                "price": cost,
                "fet": fet,
                "availability": availability,
            })

    return all_tires


def _scrape_hesselbein_catalog(supplier: Supplier, password: str, search: Optional[str] = None) -> list:
    """Login to Hesselbein DKTire via Playwright and return full tire list."""
    access_token = None
    token_type = "Bearer"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"])
            ctx = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
            page = ctx.new_page()
            page.goto("https://b2b.dktire.com/auth-signin", timeout=60000)
            page.wait_for_load_state("networkidle", timeout=30000)
            time.sleep(3)
            for sel in ['input[type="text"]', 'input[name="username"]', 'input[name="account"]']:
                try:
                    loc = page.locator(sel).first
                    if loc.is_visible(timeout=2000):
                        loc.fill(supplier.portal_username)
                        break
                except Exception:
                    continue
            for sel in ['input[type="password"]', 'input[name="password"]']:
                try:
                    loc = page.locator(sel).first
                    if loc.is_visible(timeout=2000):
                        loc.fill(password)
                        break
                except Exception:
                    continue
            for sel in ['button[type="submit"]', 'button:has-text("Sign In")', 'button:has-text("Login")']:
                try:
                    loc = page.locator(sel).first
                    if loc.is_visible(timeout=2000):
                        loc.click()
                        break
                except Exception:
                    continue
            time.sleep(5)
            page.wait_for_load_state("networkidle", timeout=30000)
            try:
                import json as _json
                auth_json = page.evaluate("() => localStorage.getItem('authUser')")
                if auth_json:
                    auth_data = _json.loads(auth_json)
                    access_token = auth_data.get("access_token")
                    token_type = auth_data.get("token_type", "Bearer")
            except Exception:
                pass
            browser.close()
    except Exception as e:
        raise ValueError(f"Playwright error: {e}")
    if not access_token:
        raise ValueError("Hesselbein login failed — could not extract access token.")
    api_headers = {
        "Authorization": f"{token_type} {access_token}",
        "Content-Type": "application/json",
        "Timezone": "America/Chicago",
    }
    api_base = "https://api-b2b.dktire.com"
    user_resp = requests.get(f"{api_base}/master/user-details", headers=api_headers, timeout=30)
    ship_to_uuid = "83373a2b-d442-41e6-8d65-531240a0ecb4"
    if user_resp.status_code == 200:
        ud = user_resp.json()
        ship_to_list = ud.get("ship_to", [])
        if isinstance(ship_to_list, list) and ship_to_list:
            first = ship_to_list[0]
            ship_to_uuid = (first.get("value", "") if isinstance(first, dict) else str(first)) or ship_to_uuid
    tires = []
    search_params: dict = {"ship_to": ship_to_uuid}
    if search:
        search_params["search"] = search
        search_params["query"] = search
    for ep in ["/product/search", "/product/tire-search", "/product/list", "/master/product-list"]:
        try:
            r = requests.get(f"{api_base}{ep}", headers=api_headers, params=search_params, timeout=30)
            if r.status_code == 200:
                data = r.json()
                raw_list = data if isinstance(data, list) else data.get(
                    "data", data.get("products", data.get("items", data.get("results", [])))
                )
                for item in raw_list:
                    if not isinstance(item, dict):
                        continue
                    tires.append({
                        "sku": item.get("item_id", item.get("sku", item.get("id", ""))),
                        "size": item.get("size_description", item.get("size", item.get("tire_size", ""))),
                        "description": item.get("item_description", item.get("description", item.get("name", ""))),
                        "brand": item.get("brand", item.get("brand_name", "")),
                        "price": str(item.get("net_price", item.get("price", item.get("unit_price", "")))),
                        "availability": str(item.get("qty_available", item.get("availability", item.get("stock", "")))),
                    })
                if tires:
                    break
        except Exception:
            continue
    return tires


def _scrape_atd_catalog(supplier: Supplier, password: str, search: Optional[str] = None) -> list:
    """Login to ATD (atd.com) dealer portal and return tire catalog.
    ATD's dealer ordering site lives at ordering.atd.com and uses a JSON product API.
    Falls back to empty list with no exception so the refresh cycle continues."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json, text/html, */*",
    })
    tires = []
    try:
        # Step 1: GET login page to extract CSRF / form fields
        base = "https://ordering.atd.com"
        login_page = session.get(f"{base}/login", timeout=30, allow_redirects=True)
        soup = BeautifulSoup(login_page.text, "lxml")

        csrf_input = soup.find("input", {"name": re.compile(r"csrf|_token|authenticity", re.I)})
        login_data: dict = {
            "username": supplier.portal_username,
            "password": password,
        }
        if csrf_input:
            login_data[csrf_input["name"]] = csrf_input.get("value", "")

        login_resp = session.post(f"{base}/login", data=login_data, timeout=30, allow_redirects=True)

        # Step 2: Try known ATD product-search JSON endpoints
        search_term = search or "tire"
        for endpoint, params in [
            (f"{base}/api/products/search", {"q": search_term, "category": "tires", "pageSize": 200}),
            (f"{base}/api/catalog/tires", {"search": search_term, "limit": 200}),
            (f"{base}/product/search.json", {"query": search_term, "type": "tire"}),
        ]:
            try:
                r = session.get(endpoint, params=params, timeout=30)
                if r.status_code == 200:
                    data = r.json()
                    raw = data if isinstance(data, list) else data.get(
                        "products", data.get("items", data.get("results", [])))
                    for item in raw:
                        if not isinstance(item, dict):
                            continue
                        tires.append({
                            "sku": str(item.get("sku", item.get("partNumber", item.get("id", "")))),
                            "size": str(item.get("size", item.get("tireSize", ""))),
                            "description": str(item.get("name", item.get("description", ""))),
                            "brand": str(item.get("brand", item.get("brandName", ""))),
                            "price": str(item.get("price", item.get("netPrice", item.get("unitPrice", "")))),
                            "availability": str(item.get("qty", item.get("availability", item.get("stock", "")))),
                        })
                    if tires:
                        break
            except Exception:
                continue
    except Exception:
        pass  # Return whatever we have; don't crash the refresh cycle
    return tires


def _scrape_km_catalog(supplier: Supplier, password: str, search: Optional[str] = None) -> list:
    """Login to K&M Tire (kmtire.com) dealer portal and return tire catalog.
    K&M uses a PHP/Laravel backend with session-based auth.
    Falls back to empty list with no exception so the refresh cycle continues."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    })
    tires = []
    try:
        base = "https://www.kmtire.com"
        # Step 1: GET login page for CSRF token
        login_page = session.get(f"{base}/login", timeout=30)
        soup = BeautifulSoup(login_page.text, "lxml")

        csrf_input = soup.find("input", {"name": re.compile(r"_token|csrf", re.I)})
        csrf_val = csrf_input.get("value", "") if csrf_input else ""

        login_resp = session.post(
            f"{base}/login",
            data={"email": supplier.portal_username, "password": password, "_token": csrf_val},
            timeout=30,
            allow_redirects=True,
        )

        # Step 2: Search for tires
        search_term = search or "tire"
        for endpoint, params in [
            (f"{base}/api/products", {"search": search_term, "category": "tires", "per_page": 200}),
            (f"{base}/catalog/search", {"q": search_term, "type": "tires"}),
            (f"{base}/products.json", {"search": search_term}),
        ]:
            try:
                r = session.get(endpoint, params=params, timeout=30)
                if r.status_code == 200:
                    data = r.json()
                    raw = data if isinstance(data, list) else data.get(
                        "data", data.get("products", data.get("items", [])))
                    for item in raw:
                        if not isinstance(item, dict):
                            continue
                        tires.append({
                            "sku": str(item.get("sku", item.get("part_number", item.get("id", "")))),
                            "size": str(item.get("size", item.get("tire_size", ""))),
                            "description": str(item.get("name", item.get("description", ""))),
                            "brand": str(item.get("brand", item.get("brand_name", ""))),
                            "price": str(item.get("price", item.get("net_price", item.get("unit_price", "")))),
                            "availability": str(item.get("qty", item.get("availability", item.get("stock", "")))),
                        })
                    if tires:
                        break
            except Exception:
                continue
    except Exception:
        pass
    return tires


def _scrape_south_gateway_catalog(supplier: Supplier, password: str, search: Optional[str] = None) -> list:
    """Stub: South Gateway catalog scraper. Returns empty list until portal structure is confirmed."""
    return []


def _scrape_mekaniq_catalog(supplier: Supplier, password: str, search: Optional[str] = None) -> list:
    """Stub: Mekaniq catalog scraper. Returns empty list until portal structure is confirmed."""
    return []


def _upsert_supplier_catalog(db: Session, supplier_id: int, owner_id: int, entries: list) -> None:
    """Delete-then-insert all catalog entries for a supplier with a shared timestamp."""
    now = dt.datetime.utcnow()
    db.query(SupplierCatalog).filter(SupplierCatalog.supplier_id == supplier_id).delete()
    for e in entries:
        db.add(SupplierCatalog(
            supplier_id=supplier_id,
            owner_id=owner_id,
            sku=str(e.get("sku") or ""),
            brand=str(e.get("brand") or ""),
            model=str(e.get("description") or ""),
            size=str(e.get("size") or ""),
            cost=str(e.get("price") or ""),
            fet=str(e.get("fet") or ""),
            availability=str(e.get("availability") or ""),
            last_updated=now,
        ))
    db.commit()


_refresh_lock = threading.Lock()
_cron_last_run_date: Optional[dt.date] = None


def _do_full_catalog_refresh(owner_id: Optional[int] = None) -> dict:
    """Scrape BZO, Hesselbein, ATD, K&M, South Gateway, and Mekaniq and upsert into supplier_catalog.
    Pass owner_id to scope to one user; None refreshes all users.
    Acquires a lock so concurrent calls are a no-op."""
    if not _refresh_lock.acquire(blocking=False):
        return {"status": "already_running"}
    results: dict = {}
    try:
        db = SessionLocal()
        try:
            for name_pattern, key, scrape_fn in [
                ("%BZO%", "bzo", _scrape_bzo_catalog),
                ("%hesselbein%", "hesselbein", _scrape_hesselbein_catalog),
                ("%ATD%", "atd", _scrape_atd_catalog),
                ("%K&M%", "km", _scrape_km_catalog),
                ("%South Gateway%", "south_gateway", _scrape_south_gateway_catalog),
                ("%Mekaniq%", "mekaniq", _scrape_mekaniq_catalog),
            ]:
                q = db.query(Supplier).filter(
                    Supplier.name.ilike(name_pattern),
                    Supplier.portal_username.isnot(None),
                    Supplier.portal_password_encrypted.isnot(None),
                    Supplier.is_active == True,
                )
                if owner_id is not None:
                    q = q.filter(Supplier.owner_id == owner_id)
                supplier = q.first()
                if not supplier:
                    results[key] = {"status": "skipped", "detail": "No credentials configured"}
                    continue
                try:
                    password = _simple_decrypt(supplier.portal_password_encrypted)
                    tires = scrape_fn(supplier, password)
                    _upsert_supplier_catalog(db, supplier.id, supplier.owner_id, tires)
                    results[key] = {"status": "ok", "count": len(tires)}
                except Exception as exc:
                    results[key] = {"status": "error", "detail": str(exc)}
        finally:
            db.close()
    finally:
        _refresh_lock.release()
    return results


def _stock_cron_thread() -> None:
    """Daemon thread: refresh supplier catalogs + QBO tokens every Sunday at 06:00 Central (UTC-6)."""
    global _cron_last_run_date
    while True:
        try:
            # Approximate Central time as UTC-6 (ignores DST — fine for a weekly job)
            now_central = dt.datetime.utcnow() - dt.timedelta(hours=6)
            if (
                now_central.weekday() == 6  # Sunday
                and now_central.hour == 6
                and _cron_last_run_date != now_central.date()
            ):
                _cron_last_run_date = now_central.date()
                print("Stock cron: starting Sunday catalog refresh + QBO token refresh...")

                # 1. Proactively refresh all QBO access tokens before catalog runs
                try:
                    db = SessionLocal()
                    try:
                        now_utc = dt.datetime.now(dt.timezone.utc)
                        tokens = db.query(QuickBooksToken).all()
                        for tok in tokens:
                            # Refresh if access token expires within 24 h
                            if tok.access_token_expires_at - now_utc < dt.timedelta(hours=24):
                                resp = requests.post(
                                    QB_TOKEN_URL,
                                    auth=(get_qb_client_id(), get_qb_client_secret()),
                                    headers={"Accept": "application/json",
                                             "Content-Type": "application/x-www-form-urlencoded"},
                                    data={"grant_type": "refresh_token",
                                          "refresh_token": tok.refresh_token},
                                    timeout=30,
                                )
                                if resp.status_code == 200:
                                    td = resp.json()
                                    tok.access_token = td["access_token"]
                                    tok.refresh_token = td["refresh_token"]
                                    tok.access_token_expires_at = now_utc + dt.timedelta(seconds=td["expires_in"])
                                    tok.refresh_token_expires_at = now_utc + dt.timedelta(
                                        seconds=td["x_refresh_token_expires_in"])
                                    db.commit()
                                    print(f"Stock cron: QBO token refreshed for user_id={tok.user_id}")
                                else:
                                    print(f"Stock cron: QBO token refresh failed for user_id={tok.user_id}: {resp.text[:200]}")
                    finally:
                        db.close()
                except Exception as qb_err:
                    print(f"Stock cron: QBO token refresh error: {qb_err}")

                # 2. Refresh all supplier catalogs (costs)
                result = _do_full_catalog_refresh()
                print(f"Stock cron: catalog refresh done — {result}")

        except Exception as e:
            print(f"Stock cron error: {e}")
        time.sleep(1800)  # check every 30 minutes


@app.post("/stock/refresh-all")
def refresh_all_stock(
    current_user: User = Depends(get_current_user),
):
    """Scrape BZO and Hesselbein full catalogs and upsert into supplier_catalog.
    Takes 1-3 minutes. The Monday 5 AM cron also calls this automatically."""
    result = _do_full_catalog_refresh(owner_id=current_user.id)
    return result


# =============================================================================
# SUPPLIER STOCK — cached catalog reads (instant)
# =============================================================================

@app.get("/stock/bzo")
def get_bzo_stock(
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Read BZO catalog from local cache. Use POST /stock/refresh-all to update."""
    supplier = db.query(Supplier).filter(
        Supplier.owner_id == current_user.id,
        Supplier.name.ilike("%BZO%"),
    ).first()
    if not supplier:
        raise HTTPException(status_code=404, detail="BZO supplier not configured.")
    q = db.query(SupplierCatalog).filter(SupplierCatalog.supplier_id == supplier.id)
    if search:
        term = f"%{search}%"
        q = q.filter(or_(
            SupplierCatalog.size.ilike(term),
            SupplierCatalog.brand.ilike(term),
            SupplierCatalog.sku.ilike(term),
            SupplierCatalog.model.ilike(term),
        ))
    rows = q.order_by(SupplierCatalog.size).limit(500).all()
    last_updated = rows[0].last_updated.isoformat() if rows else None
    tires = [
        {"sku": r.sku, "brand": r.brand, "size": r.size,
         "description": r.model, "price": r.cost, "fet": r.fet, "availability": r.availability}
        for r in rows
    ]
    return {"supplier": "BZO", "tires": tires, "total": len(tires), "last_updated": last_updated}


@app.get("/stock/hesselbein")
def get_hesselbein_stock(
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Read Hesselbein catalog from local cache. Use POST /stock/refresh-all to update."""
    supplier = db.query(Supplier).filter(
        Supplier.owner_id == current_user.id,
        Supplier.name.ilike("%hesselbein%"),
    ).first()
    if not supplier:
        raise HTTPException(status_code=404, detail="Hesselbein supplier not configured.")
    q = db.query(SupplierCatalog).filter(SupplierCatalog.supplier_id == supplier.id)
    if search:
        term = f"%{search}%"
        q = q.filter(or_(
            SupplierCatalog.size.ilike(term),
            SupplierCatalog.brand.ilike(term),
            SupplierCatalog.sku.ilike(term),
            SupplierCatalog.model.ilike(term),
        ))
    rows = q.order_by(SupplierCatalog.size).limit(500).all()
    last_updated = rows[0].last_updated.isoformat() if rows else None
    tires = [
        {"sku": r.sku, "brand": r.brand, "size": r.size,
         "description": r.model, "price": r.cost, "availability": r.availability}
        for r in rows
    ]
    return {"supplier": "Hesselbein", "tires": tires, "total": len(tires), "last_updated": last_updated}


@app.get("/stock/price-check")
def price_check(
    size: str = Query(..., description="Tire size the customer needs, e.g. 225/65R17"),
    brand: Optional[str] = Query(None, description="Optional brand filter"),
    live: bool = Query(False, description="Re-scrape BZO+Hesselbein now instead of using cache"),
    contact_id: Optional[int] = Query(None, description="Attach this lookup to a CRM contact"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Cross-supplier lowest-price search triggered by a customer's tire size request.
    Reads the cached Sunday catalog — instant (<100ms).
    Pass live=true to scrape BZO+Hesselbein on demand for that exact size (~30s).
    Returns all supplier results sorted by landed cost (price + FET) cheapest first."""

    if live:
        # On-demand scrape for this specific size — re-uses the single-size search path
        for name_pattern, scrape_fn in [
            ("%BZO%", _scrape_bzo_catalog),
            ("%hesselbein%", _scrape_hesselbein_catalog),
        ]:
            supplier = db.query(Supplier).filter(
                Supplier.owner_id == current_user.id,
                Supplier.name.ilike(name_pattern),
                Supplier.portal_username.isnot(None),
                Supplier.portal_password_encrypted.isnot(None),
                Supplier.is_active == True,
            ).first()
            if not supplier:
                continue
            try:
                password = _simple_decrypt(supplier.portal_password_encrypted)
                tires = scrape_fn(supplier, password, search=size)
                _upsert_supplier_catalog(db, supplier.id, supplier.owner_id, tires)
            except Exception:
                pass  # Fall through to cached results

    # Read from cache — fuzzy size match so "225/65R17" also catches "225/65R017" etc.
    size_term = f"%{size.strip()}%"
    q = (
        db.query(SupplierCatalog, Supplier.name.label("supplier_name"))
        .join(Supplier, Supplier.id == SupplierCatalog.supplier_id)
        .filter(
            Supplier.owner_id == current_user.id,
            SupplierCatalog.size.ilike(size_term),
        )
    )
    if brand:
        q = q.filter(SupplierCatalog.brand.ilike(f"%{brand}%"))

    rows = q.all()

    def _to_float(val) -> Optional[float]:
        try:
            return float(str(val).replace("$", "").replace(",", "").strip())
        except Exception:
            return None

    results = []
    for row, supplier_name in rows:
        price_f = _to_float(row.cost)
        fet_f = _to_float(row.fet) or 0.0
        results.append({
            "supplier": supplier_name,
            "brand": row.brand,
            "size": row.size,
            "description": row.model,
            "price": row.cost,
            "price_float": price_f,
            "fet": row.fet,
            "landed": round(price_f + fet_f, 2) if price_f is not None else None,
            "availability": row.availability,
            "sku": row.sku,
            "last_updated": row.last_updated.isoformat() if row.last_updated else None,
        })

    # Sort by landed cost (price + FET), nulls last
    results.sort(key=lambda r: (r["landed"] is None, r["landed"] or 0))

    cheapest = results[0] if results else None

    # Optionally include contact name for display in UI
    customer_name = None
    if contact_id:
        contact = db.query(Contact).filter(
            Contact.id == contact_id,
            Contact.owner_id == current_user.id,
        ).first()
        if contact:
            customer_name = f"{contact.first_name or ''} {contact.last_name or ''}".strip() or contact.company

    return {
        "size": size,
        "brand_filter": brand,
        "contact_id": contact_id,
        "customer_name": customer_name,
        "total": len(results),
        "cheapest": cheapest,
        "results": results,
        "live_scraped": live,
    }


# =============================================================================
# QUICKBOOKS INVOICES
# =============================================================================

class InvoiceLineItemIn(BaseModel):
    qb_item_id: str
    inventory_item_id: Optional[int] = None
    description: str = ""
    quantity: int
    unit_price: float
    fet_per_unit: float = 0.0


class CreateInvoiceRequest(BaseModel):
    customer_ref: str  # QBO customer Id
    customer_name: str = ""
    line_items: List[InvoiceLineItemIn]
    memo: Optional[str] = None

# Force Pydantic v2 to resolve forward refs under `from __future__ import annotations`
InvoiceLineItemIn.model_rebuild()
CreateInvoiceRequest.model_rebuild()


@app.get("/quickbooks/invoices")
def list_qb_invoices(
    max_results: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List recent invoices from QuickBooks."""
    access_token, realm_id = get_qb_access_token(current_user.id, db)

    resp = requests.get(
        f"{get_qb_api_base()}/v3/company/{realm_id}/query",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        params={"query": f"SELECT * FROM Invoice MAXRESULTS {max_results} ORDER BY MetaData.LastUpdatedTime DESC"},
        timeout=30
    )

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"QuickBooks API error: {resp.text[:300]}")

    invoices = resp.json().get("QueryResponse", {}).get("Invoice", [])

    result = []
    for inv in invoices:
        result.append({
            "id": inv.get("Id"),
            "doc_number": inv.get("DocNumber", ""),
            "date": inv.get("TxnDate", ""),
            "due_date": inv.get("DueDate", ""),
            "customer_name": inv.get("CustomerRef", {}).get("name", ""),
            "customer_ref": inv.get("CustomerRef", {}).get("value", ""),
            "total": inv.get("TotalAmt", 0),
            "balance": inv.get("Balance", 0),
            "status": "Paid" if (inv.get("Balance", 0) == 0 and inv.get("TotalAmt", 0) > 0) else "Open",
            "memo": inv.get("CustomerMemo", {}).get("value", "") if isinstance(inv.get("CustomerMemo"), dict) else "",
            "line_count": len(inv.get("Line", [])),
        })

    return {"invoices": result, "total": len(result)}


@app.post("/quickbooks/invoices/create")
def create_qb_invoice(
    req: CreateInvoiceRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a QuickBooks invoice, deduct CRM inventory, log Firebase sale movement."""
    access_token, realm_id = get_qb_access_token(current_user.id, db)

    # Build QBO invoice payload
    lines = []
    total_amount = 0.0
    total_fet = 0.0

    for li in req.line_items:
        line_total = li.quantity * li.unit_price
        total_amount += line_total
        total_fet += li.quantity * li.fet_per_unit

        lines.append({
            "Amount": round(line_total, 2),
            "DetailType": "SalesItemLineDetail",
            "Description": li.description or "",
            "SalesItemLineDetail": {
                "ItemRef": {"value": li.qb_item_id},
                "Qty": li.quantity,
                "UnitPrice": li.unit_price,
            }
        })

    # Add FET line item if any
    if total_fet > 0:
        lines.append({
            "Amount": round(total_fet, 2),
            "DetailType": "SalesItemLineDetail",
            "Description": "Federal Excise Tax (FET)",
            "SalesItemLineDetail": {
                "ItemRef": {"value": "7"},  # Income account item
                "Qty": 1,
                "UnitPrice": round(total_fet, 2),
            }
        })

    invoice_payload = {
        "CustomerRef": {"value": req.customer_ref},
        "Line": lines,
    }
    if req.memo:
        invoice_payload["CustomerMemo"] = {"value": req.memo}

    resp = requests.post(
        f"{get_qb_api_base()}/v3/company/{realm_id}/invoice",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        json=invoice_payload,
        timeout=30
    )

    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=resp.status_code, detail=f"QuickBooks invoice error: {resp.text[:400]}")

    qb_invoice = resp.json().get("Invoice", {})
    invoice_id = qb_invoice.get("Id", "")
    doc_number = qb_invoice.get("DocNumber", invoice_id)

    # Deduct inventory quantities
    deducted_items = []
    for li in req.line_items:
        if li.inventory_item_id:
            inv_item = db.query(InventoryItem).filter(
                InventoryItem.id == li.inventory_item_id,
                InventoryItem.owner_id == current_user.id
            ).first()
            if inv_item:
                inv_item.quantity = max(0, inv_item.quantity - li.quantity)
                txn = InventoryTransaction(
                    item_id=inv_item.id,
                    owner_id=current_user.id,
                    transaction_type="sell",
                    quantity=-li.quantity,
                    unit_cost=li.unit_price,
                    reference=f"INV-{doc_number}",
                    notes=f"QBO Invoice #{doc_number} - {req.customer_name}",
                )
                db.add(txn)
                deducted_items.append({
                    "sku": inv_item.sku,
                    "name": inv_item.name,
                    "qty_deducted": li.quantity,
                    "new_qty": inv_item.quantity,
                })
    db.commit()

    # Create Firebase sale movement
    firebase_line_items = [
        {
            "sku": li.qb_item_id,
            "description": li.description,
            "quantity": str(li.quantity),
            "unit_price": str(li.unit_price),
            "fet": str(li.fet_per_unit),
            "total": str(round(li.quantity * li.unit_price, 2)),
        }
        for li in req.line_items
    ]

    try:
        firebase_token = get_firebase_auth_token()
        movement_data = {
            "poNumber": f"INV-{doc_number}",
            "supplier": f"Sale to {req.customer_name or req.customer_ref}",
            "type": "sale",
            "status": "completed",
            "date": dt.datetime.now().isoformat(),
            "total": str(round(total_amount + total_fet, 2)),
            "customerRef": req.customer_ref,
            "customerName": req.customer_name,
            "qbInvoiceId": invoice_id,
            "qbDocNumber": doc_number,
            "items": firebase_line_items,
            "createdAt": dt.datetime.now().isoformat(),
            "autoReceived": False,
        }
        create_firebase_movement(firebase_token, movement_data)
    except Exception:
        pass  # Firebase movement is best-effort; don't fail the invoice

    return {
        "ok": True,
        "invoice_id": invoice_id,
        "doc_number": doc_number,
        "total": total_amount + total_fet,
        "deducted_items": deducted_items,
        "qb_invoice": qb_invoice,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
