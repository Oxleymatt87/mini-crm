# === main.py (FULL) ===
from __future__ import annotations
import os, csv, io, datetime as dt
from typing import Optional, List, Annotated, Tuple, Dict, Any

import requests
from fastapi import FastAPI, Depends, HTTPException, Query, Path, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse, PlainTextResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, field_validator, EmailStr
from sqlalchemy import (
    create_engine, String, Integer, Boolean, DateTime, Text, Enum, ForeignKey,
    Float, func, select, Index, and_, or_, asc, desc
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session

def _load_env_file() -> None:
    if os.path.exists('.env'):
        with open('.env', 'r', encoding='utf-8') as f:
            for line in f:
                line=line.strip()
                if not line or line.startswith('#') or '=' not in line: continue
                k,v=line.split('=',1); os.environ.setdefault(k.strip(), v.strip())
_load_env_file()

JWT_SECRET = os.getenv('JWT_SECRET', 'change-this-in-production')
JWT_ALG = 'HS256'
JWT_EXPIRE_MIN = int(os.getenv('JWT_EXPIRE_MIN', '1440'))
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./crm.db')
GOOGLE_MAPS_API_KEY = os.getenv('GOOGLE_MAPS_API_KEY', '')
PORT = int(os.getenv('PORT', '10000'))  # Render default we’ll use in startCommand

class Base(DeclarativeBase): pass
engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/login')

def hash_password(p:str)->str: return pwd_context.hash(p)
def verify_password(p:str, h:str)->bool: return pwd_context.verify(p, h)
def create_access_token(subj:str, minutes:int=JWT_EXPIRE_MIN)->str:
    now=dt.datetime.utcnow(); exp=now+dt.timedelta(minutes=minutes)
    return jwt.encode({'sub':subj,'iat':int(now.timestamp()),'exp':int(exp.timestamp())}, JWT_SECRET, algorithm=JWT_ALG)
def decode_token(t:str)->str:
    try:
        payload=jwt.decode(t, JWT_SECRET, algorithms=[JWT_ALG])
        sub=payload.get('sub'); 
        if not sub: raise JWTError('Missing sub')
        return str(sub)
    except JWTError as e:
        raise HTTPException(401,'Invalid or expired token') from e

class User(Base):
    __tablename__='users'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    email: Mapped[str]=mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str]=mapped_column(String(255))
    hashed_password: Mapped[str]=mapped_column(String(255))
    is_active: Mapped[bool]=mapped_column(Boolean, default=True)
    is_admin: Mapped[bool]=mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime]=mapped_column(DateTime(timezone=True), server_default=func.now())
    contacts: Mapped[List['Contact']]=relationship(back_populates='owner', cascade='all, delete-orphan')

class Contact(Base):
    __tablename__='contacts'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int]=mapped_column(ForeignKey('users.id', ondelete='CASCADE'), index=True)
    first_name: Mapped[str]=mapped_column(String(120), index=True)
    last_name: Mapped[str]=mapped_column(String(120), index=True)
    email: Mapped[Optional[str]]=mapped_column(String(255), index=True)
    phone: Mapped[Optional[str]]=mapped_column(String(40), index=True)
    company: Mapped[Optional[str]]=mapped_column(String(255), index=True)
    position: Mapped[Optional[str]]=mapped_column(String(255))
    notes: Mapped[Optional[str]]=mapped_column(Text)
    address_line1: Mapped[Optional[str]]=mapped_column(String(255))
    address_line2: Mapped[Optional[str]]=mapped_column(String(255))
    city: Mapped[Optional[str]]=mapped_column(String(120), index=True)
    state: Mapped[Optional[str]]=mapped_column(String(120), index=True)
    postal_code: Mapped[Optional[str]]=mapped_column(String(40), index=True)
    country: Mapped[Optional[str]]=mapped_column(String(120), index=True)
    latitude: Mapped[Optional[float]]=mapped_column(Float, index=True)
    longitude: Mapped[Optional[float]]=mapped_column(Float, index=True)
    last_contacted_at: Mapped[Optional[dt.datetime]]=mapped_column(DateTime(timezone=True))
    next_follow_up_at: Mapped[Optional[dt.datetime]]=mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[dt.datetime]=mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[dt.datetime]=mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    owner: Mapped[User]=relationship(back_populates='contacts')
Index('ix_contacts_name', Contact.first_name, Contact.last_name)
Index('ix_contacts_company_email', Contact.company, Contact.email)
InteractionKind = Enum('call','email','meeting','note', name='interaction_kind')

class Interaction(Base):
    __tablename__='interactions'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    contact_id: Mapped[int]=mapped_column(ForeignKey('contacts.id', ondelete='CASCADE'), index=True)
    owner_id: Mapped[int]=mapped_column(ForeignKey('users.id', ondelete='CASCADE'), index=True)
    kind: Mapped[str]=mapped_column(InteractionKind)
    summary: Mapped[str]=mapped_column(Text)
    occurred_at: Mapped[dt.datetime]=mapped_column(DateTime(timezone=True), default=func.now(), index=True)
    created_at: Mapped[dt.datetime]=mapped_column(DateTime(timezone=True), server_default=func.now())

class Token(BaseModel): access_token:str; token_type:str='bearer'
class UserCreate(BaseModel):
    email: EmailStr; full_name:str; password:str
    @field_validator('password') @classmethod
    def strong(cls,v): 
        if len(v)<6: raise ValueError('password too short'); return v
class UserOut(BaseModel):
    id:int; email:EmailStr; full_name:str; is_active:bool; is_admin:bool; created_at:dt.datetime
class ContactCreate(BaseModel):
    first_name:str; last_name:str
    email:Optional[EmailStr]=None; phone:Optional[str]=None
    company:Optional[str]=None; position:Optional[str]=None; notes:Optional[str]=None
    next_follow_up_at:Optional[dt.datetime]=None
    address_line1:Optional[str]=None; address_line2:Optional[str]=None
    city:Optional[str]=None; state:Optional[str]=None; postal_code:Optional[str]=None; country:Optional[str]=None
class ContactUpdate(BaseModel):
    first_name:Optional[str]=None; last_name:Optional[str]=None; email:Optional[EmailStr]=None; phone:Optional[str]=None
    company:Optional[str]=None; position:Optional[str]=None; notes:Optional[str]=None
    last_contacted_at:Optional[dt.datetime]=None; next_follow_up_at:Optional[dt.datetime]=None
    address_line1:Optional[str]=None; address_line2:Optional[str]=None; city:Optional[str]=None; state:Optional[str]=None; postal_code:Optional[str]=None; country:Optional[str]=None
class ContactOut(BaseModel):
    id:int; first_name:str; last_name:str
    email:Optional[EmailStr]=None; phone:Optional[str]=None
    company:Optional[str]=None; position:Optional[str]=None; notes:Optional[str]=None
    address_line1:Optional[str]=None; address_line2:Optional[str]=None; city:Optional[str]=None; state:Optional[str]=None; postal_code:Optional[str]=None; country:Optional[str]=None
    latitude:Optional[float]=None; longitude:Optional[float]=None
    last_contacted_at:Optional[dt.datetime]=None; next_follow_up_at:Optional[dt.datetime]=None
    created_at:dt.datetime; updated_at:dt.datetime
class InteractionCreate(BaseModel): kind:str; summary:str; occurred_at:Optional[dt.datetime]=None
class InteractionOut(BaseModel): id:int; contact_id:int; kind:str
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT)
