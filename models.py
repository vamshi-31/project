from sqlalchemy import Column, Integer, String, Boolean, Date, ForeignKey, LargeBinary
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    is_active = Column(Boolean, default=False)  # Default value for new users

    # Define relationships
    events = relationship("Event", back_populates="owner")
    pending_events = relationship("PendingEvent", back_populates="user")  # Relationship to PendingEvent

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
    user_id = Column(Integer, ForeignKey("users.id"))  # ForeignKey references User table
    status = Column(String, default="pending")  # Added status to track approval

    # Define relationship with User
    owner = relationship("User", back_populates="events")
    forms = relationship("EventForm", back_populates="event", cascade="all, delete-orphan")  # Added cascade for deletion

class EventForm(Base):
    __tablename__ = "registrations"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("events.id"))
    name = Column(String, index=True)
    email = Column(String, index=True)
    phoneno = Column(String)
    dropdown = Column(String)
    image = Column(LargeBinary)

    event = relationship("Event", back_populates="forms")

class ImageModel(Base):
    __tablename__ = "images"
    id = Column(Integer, primary_key=True)
    filename = Column(String, nullable=False)
    data = Column(LargeBinary, nullable=False)

