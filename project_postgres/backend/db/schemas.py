from pydantic import BaseModel
from typing import Dict, Any, Optional
from datetime import datetime


class UserCreate(BaseModel):
    email: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    sex: Optional[str] = None
    department: Optional[str] = None
    group_name: Optional[str] = None


class UserLogin(BaseModel):
    email: str
    password: str


class SignupOtpRequest(BaseModel):
    first_name: str
    last_name: str
    email: str
    sex: str
    department: str
    group_name: str
    password: str


class SignupOtpVerify(BaseModel):
    email: str
    code: str


class PasswordResetRequest(BaseModel):
    email: str


class PasswordResetConfirm(BaseModel):
    email: str
    code: str
    new_password: str


class UserResponse(BaseModel):
    id: int
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    sex: Optional[str] = None
    department: Optional[str] = None
    group_name: Optional[str] = None

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
