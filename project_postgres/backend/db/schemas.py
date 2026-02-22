from pydantic import BaseModel
from typing import Dict, Any, Optional
from datetime import datetime


class UserCreate(BaseModel):
    email: str
    password: str


class UserLogin(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    id: int
    email: str

    class Config:
        from_attributes = True


class ScanCreate(BaseModel):
    user_id: int
    scan_type: str
    target: str
    status: str
    threat_score: int
    details: Dict[str, Any]


class ScanResponse(BaseModel):
    id: int
    user_id: int
    scan_type: str
    target: str
    status: str
    threat_score: int
    created_at: datetime

    class Config:
        from_attributes = True


class AuditLogResponse(BaseModel):
    id: int
    user_id: int
    action: str
    details: str
    timestamp: datetime

    class Config:
        from_attributes = True
