from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()


# ── Table des utilisateurs du système ──────────────────────────
class User(Base):
    __tablename__ = 'users'

    id            = Column(Integer, primary_key=True)
    username      = Column(String(50), unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)   # stocké chiffré
    role          = Column(String(20), nullable=False)  # admin / operateur / lecteur
    actif         = Column(Boolean, default=True)
    created_at    = Column(DateTime, default=datetime.utcnow)

    logs = relationship('AccessLog', back_populates='user')


# ── Table des clients (données sensibles) ──────────────────────
class Client(Base):
    __tablename__ = 'clients'

    id            = Column(Integer, primary_key=True)
    nom           = Column(String(100), nullable=False)
    email         = Column(String(100), unique=True, nullable=False)

    # Colonnes sensibles → stockées chiffrées (AES-256-GCM)
    carte_credit  = Column(Text, nullable=True)   # chiffré
    telephone     = Column(Text, nullable=True)   # chiffré
    adresse       = Column(Text, nullable=True)   # chiffré

    # Hash déterministe HMAC-SHA256 pour recherche
    carte_hash    = Column(String(64), nullable=True, index=True)
    telephone_hash= Column(String(64), nullable=True, index=True)

    created_at    = Column(DateTime, default=datetime.utcnow)


# ── Table des clés par rôle ────────────────────────────────────
class RoleKey(Base):
    __tablename__ = 'role_keys'

    id         = Column(Integer, primary_key=True)
    role       = Column(String(20), unique=True, nullable=False)
    key_salt   = Column(Text, nullable=False)   # sel HKDF stocké en hex
    version    = Column(Integer, default=1)     # pour rotation des clés
    created_at = Column(DateTime, default=datetime.utcnow)


# ── Journal des accès (signé) ──────────────────────────────────
class AccessLog(Base):
    __tablename__ = 'access_logs'

    id         = Column(Integer, primary_key=True)
    user_id    = Column(Integer, ForeignKey('users.id'), nullable=False)
    table_name = Column(String(50), nullable=False)
    column_name= Column(String(50), nullable=False)
    action     = Column(String(20), nullable=False)  # READ / WRITE / DENIED
    timestamp  = Column(DateTime, default=datetime.utcnow)
    signature  = Column(Text, nullable=False)   # HMAC-SHA256 de l'entrée

    user = relationship('User', back_populates='logs')
