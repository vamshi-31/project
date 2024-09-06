from sqlalchemy import Column, Integer, String, Boolean, Date, ForeignKey
from sqlalchemy.dialects.postgresql import BYTEA
from sqlalchemy.orm import relationship
from database import Base
import uuid

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    is_active = Column(Boolean, default=False)

    events = relationship("Event", back_populates="owner")
    pending_events = relationship("PendingEvent", back_populates="user")

class PendingEvent(Base):
    __tablename__ = "pending_requests"

    id = Column(Integer, primary_key=True, index=True)
    event_name = Column(String, index=True)
    venue_address = Column(String)
    event_date = Column(Date)
    audience = Column(Boolean, default=False)
    delegates = Column(Boolean, default=False)
    speaker = Column(Boolean, default=False)
    nri = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey('users.id'))
    status = Column(String, default="pending")
    token = Column(String, unique=True, default=lambda: str(uuid.uuid4()))  # Add this line

    user = relationship("User", back_populates="pending_events")

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    event_name = Column(String, index=True)
    venue_address = Column(String, index=True)
    event_date = Column(Date)
    audience = Column(Boolean, default=False)
    delegates = Column(Boolean, default=False)
    speaker = Column(Boolean, default=False)
    nri = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    status = Column(String, default="pending")
    token = Column(String, unique=True, index=True)  # Token column

    owner = relationship("User", back_populates="events")
    forms = relationship("EventForm", back_populates="event", cascade="all, delete-orphan")


class EventForm(Base):
    __tablename__ = "registrations"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("events.id"))
    name = Column(String, index=True)
    email = Column(String, index=True)
    phoneno = Column(String)
    dropdown = Column(String)
    qr_code = Column(BYTEA)

    event = relationship("Event", back_populates="forms")

class ImageModel(Base):
    __tablename__ = "images"
    id = Column(Integer, primary_key=True)
    event_id = Column(Integer, ForeignKey("events.id"), unique=True, nullable=False)
    filename = Column(String, nullable=False)
    data = Column(BYTEA, nullable=False)
