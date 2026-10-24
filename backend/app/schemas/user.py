import uuid
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, model_validator, ConfigDict
from typing import Optional



class UserBase(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=255)


class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=128)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(UserBase):
    id: uuid.UUID
    role: str
    token_version: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserStatusUpdate(BaseModel):
    is_active: bool


class UserRoleUpdate(BaseModel):
    role: str = Field(pattern="^(admin|user)$")


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(default=None, min_length=2, max_length=255)
    current_password: Optional[str] = Field(default=None, min_length=8, max_length=128)
    new_password: Optional[str] = Field(default=None, min_length=8, max_length=128)

    @model_validator(mode="after")
    def validate_update(self):
        if all(
            value is None
            for value in (
                self.email,
                self.full_name,
                self.new_password,
            )
        ):
            raise ValueError("Provide at least one field to update")

        if self.new_password is not None and self.current_password is None:
            raise ValueError("Current password is required to change password")

        if self.current_password is not None and self.email is None and self.full_name is None and self.new_password is None:
            raise ValueError("Provide a field to update")

        return self
