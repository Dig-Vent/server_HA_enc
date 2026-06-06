import uuid
import datetime
from sqlalchemy import Column, String, Integer, DateTime, LargeBinary, ForeignKey, Text
from pydantic import BaseModel, Field
from typing import List, Optional
from server.database import Base

# ==========================================
# SQLAlchemy Models
# ==========================================

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=True)  # Nullable because passkey-only users don't need a password
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class PasskeyCredential(Base):
    __tablename__ = "passkey_credentials"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    credential_id = Column(LargeBinary, unique=True, nullable=False, index=True)
    public_key = Column(LargeBinary, nullable=False)
    sign_count = Column(Integer, default=0, nullable=False)
    transports = Column(String(255), default="[]")  # JSON list of transports
    name = Column(String(100), default="Passkey")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class Session(Base):
    __tablename__ = "sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    device_id = Column(String(100), nullable=False)
    token = Column(String(512), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)


class Conversation(Base):
    __tablename__ = "conversations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    participants = Column(Text, nullable=False)  # JSON list of user_ids


class Message(Base):
    __tablename__ = "messages"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    conversation_id = Column(String(36), ForeignKey("conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    sender_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    text = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)


# ==========================================
# Pydantic Schemas
# ==========================================

class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    token: str
    user_id: str
    username: str

class PasskeyRegisterCompleteRequest(BaseModel):
    credential: str  # JSON representation of the WebAuthn registration response

class PasskeyLoginCompleteRequest(BaseModel):
    credential: str  # JSON representation of the WebAuthn assertion response

class MessageCreate(BaseModel):
    text: str

class MessageResponse(BaseModel):
    id: str
    sender_id: str
    sender_name: str
    text: str
    timestamp: datetime.datetime
    is_sent_by_me: bool

class ConversationResponse(BaseModel):
    id: str
    participants: List[str]  # list of usernames
    last_message: Optional[str] = None
    last_message_time: Optional[datetime.datetime] = None
