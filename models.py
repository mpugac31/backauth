from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from database import Base

# Database models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True, default="NewUser")
    email = Column(String, unique=True, index=True)
    password = Column(String)
    profile_picture = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)