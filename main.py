from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, constr
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer

 #Налаштування бази даних
DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Контекст для хешування паролів
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Конфігурація JWT
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

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

class UserLogin(BaseModel):
    """Схема для входу користувача."""
    email: EmailStr
    password: str

class Token(BaseModel):
    """Схема для відповіді з токеном."""
    access_token: str
    token_type: str


def get_db():
    """
    Функція для отримання сесії бази даних.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
def create_access_token(data: dict, expires_delta: timedelta):
    """Створення JWT токена."""
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/register/")
def register_user(user: UserRegister, db: Session = Depends(get_db)):
    """  для реєстрації або перевірки користувача.
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
@app.post("/login/", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    """Логін користувача і видача JWT токена."""
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not pwd_context.verify(user.password, db_user.password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    access_token = create_access_token(
        data={"sub": db_user.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}
@app.get("/user_info/")
def get_user_info(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Отримує інформацію про користувача на основі токена."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return {"user_id": user.id, "email": user.email, "username": user.username}