from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session

from database import Base, engine, SessionLocal
from auth import get_current_user, create_access_token, oauth2_scheme, pwd_context
from schemas import UserRegister, UserLogin, Token
from models import User
from routers.user_router import user_router

# Create the database tables
Base.metadata.create_all(bind=engine)

# Initialize FastAPI
app = FastAPI()

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app.include_router(user_router)