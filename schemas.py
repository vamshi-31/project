from pydantic import BaseModel
from typing import Optional
from enum import Enum

class EventStatusEnum(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

class UserSchema(BaseModel):
    email: str
    password: str
    is_active: bool

    class Config:
        from_attributes = True

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

class EventResponse(EventCreate):
    id: int
    token: str  # Add this field to include the event token

    class Config:
        from_attributes = True

class EventFormCreate(BaseModel):
    event_id: int
    name: str
    email: str
    phoneno: str
    dropdown: str
    qr_code: str  # Ensure this is a string (hex or base64 encoded)

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

    class Config:
        from_attributes = True

class ImageBase(BaseModel):
    filename: str
    event_id: int

class ImageCreate(ImageBase):
    data: bytes

class ImageResponse(BaseModel):
    id: int
    event_id: int
    filename: str

    class Config:
        from_attributes = True
