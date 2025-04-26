from pydantic import BaseModel, EmailStr, constr

class UserRegister(BaseModel):
    email: EmailStr
    password: constr(min_length=6, max_length=50)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str