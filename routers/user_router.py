from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import timedelta

from database import SessionLocal
from auth import create_access_token, get_current_user, pwd_context, oauth2_scheme, ACCESS_TOKEN_EXPIRE_MINUTES
from schemas import UserRegister, UserLogin, Token
from models import User

user_router = APIRouter()

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@user_router.post("/register/")
def register_user(user: UserRegister, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        if not pwd_context.verify(user.password, existing_user.password):
            raise HTTPException(status_code=400, detail="Incorrect password")
        return {
            "message": "User already registered",
            "user_id": existing_user.id,
            "email": existing_user.email,
            "username": existing_user.username
        }

    hashed_password = pwd_context.hash(user.password)
    new_user = User(email=user.email, password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "User registered successfully",
        "user_id": new_user.id,
        "email": new_user.email,
        "username": new_user.username
    }

@user_router.post("/login/", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not pwd_context.verify(user.password, db_user.password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    access_token = create_access_token(
        data={"sub": db_user.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@user_router.get("/user_info/")
def get_user_info(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    return {"user_id": user.id, "email": user.email, "username": user.username}