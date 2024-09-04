from pydantic import BaseModel
from typing import Optional
from enum import Enum

# Schema for User creation and response
class EventStatusEnum(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
class UserSchema(BaseModel):
    email: str
    password: str
    is_active: bool

    class Config:
        from_attributes = True  # Updated from 'orm_mode' to 'from_attributes' in Pydantic v2

class EventCreate(BaseModel):
    event_name: str
    venue_address: str
    event_date: str
    audience: bool
    delegates: bool
    speaker: bool
    nri: bool
    user_id: int
    status: Optional[EventStatusEnum] = EventStatusEnum.PENDING


# Schema for Event response including the user_id to show association
class EventResponse(EventCreate):
    id: int
    user_id: int  # Added user_id to show which user the event belongs to

    class Config:
        from_attributes = True

# Schema for Event Form creation
class EventFormCreate(BaseModel):
    event_id: int
    name: str
    email: str
    phoneno: str
    dropdown: str
    qr_code:str

# Schema for Event Form response
class EventFormResponse(EventFormCreate):
    id: int

    class Config:
        from_attributes = True

class UserDetails(BaseModel):
    id: int
    name: str
    email: str
    phoneno: str
    dropdown: str
    qr_code: str

