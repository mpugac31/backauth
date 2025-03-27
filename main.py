from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, constr

 #Налаштування бази даних
DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Контекст для хешування паролів
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Оголошення моделі користувача
class User(Base):
    """
    Модель користувача для збереження в базі даних.
    - id: Унікальний ідентифікатор користувача.
    - username: Ім'я користувача (за замовчуванням 'NewUser').
    - email: Унікальна електронна пошта.
    - password: Хешований пароль.
    - profile_picture: (Необов'язкове) посилання на аватар користувача.
    - created_at: Дата та час створення запису.
    """
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True, default="NewUser")
    email = Column(String, unique=True, index=True)
    password = Column(String)
    profile_picture = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


# Створення таблиць у базі даних
Base.metadata.create_all(bind=engine)

# Ініціалізація FastAPI
app = FastAPI()


# Схема для валідації вхідних даних
class UserRegister(BaseModel):
    email: EmailStr
    password: constr(min_length=6, max_length=50)


def get_db():
    """
    Функція для отримання сесії бази даних.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/register/")
def register_user(user: UserRegister, db: Session = Depends(get_db)):
    """ Ендпоінт для реєстрації або перевірки користувача.
    - email: Унікальна електронна пошта.
    - password: Пароль користувача (мінімум 6 символів, максимум 50).
    - db: Сесія бази даних (автоматично підставляється через Depends(get_db)).

    Якщо email вже існує, перевіряється правильність пароля. Якщо не існує — створюється новий акаунт."""
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

    hashed_password = pwd_context.hash(user.password)#хешування паролю
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