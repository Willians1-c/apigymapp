"""API de GymApp: registro, login (JWT) y CRUD de rutinas.

Ejecutar:  uvicorn main:app --host 0.0.0.0 --port 8000 --reload
Documentación interactiva:  http://localhost:8000/docs
"""
import os
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import Boolean, ForeignKey, Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "mysql+pymysql://root:root@localhost:3306/gymapp")
SECRET_KEY = os.getenv("SECRET_KEY", "maxesunperromuybonitotremendopug")
ALGORITHM = "HS256"
TOKEN_HORAS = 24

# ---------------------------------------------------------------- Base de datos
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False)


class Base(DeclarativeBase):
    pass


class Usuario(Base):
    __tablename__ = "usuarios"
    id: Mapped[int] = mapped_column(primary_key=True)
    nombre: Mapped[str] = mapped_column(String(100))
    correo: Mapped[str] = mapped_column(String(150), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))


class Rutina(Base):
    __tablename__ = "rutinas"
    id: Mapped[int] = mapped_column(primary_key=True)
    nombre: Mapped[str] = mapped_column(String(100))
    grupo_muscular: Mapped[str] = mapped_column(String(30))
    series: Mapped[int] = mapped_column(Integer)
    repeticiones: Mapped[int] = mapped_column(Integer)
    nivel: Mapped[str] = mapped_column(String(20))
    activa: Mapped[bool] = mapped_column(Boolean, default=True)
    usuario_id: Mapped[int] = mapped_column(ForeignKey("usuarios.id", ondelete="CASCADE"))


# Crea las tablas si no existen (schema.sql hace lo mismo de forma explícita)
Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------- Schemas
GrupoMuscular = Literal["Pecho", "Espalda", "Pierna", "Hombro", "Brazo", "Core"]
Nivel = Literal["Principiante", "Intermedio", "Avanzado"]


class RegisterIn(BaseModel):
    nombre: str = Field(min_length=2, max_length=100)
    correo: EmailStr
    password: str = Field(min_length=8, max_length=72)


class LoginIn(BaseModel):
    correo: EmailStr
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    nombre: str
    correo: str


class AuthOut(BaseModel):
    token: str
    user: UserOut


class RutinaIn(BaseModel):
    nombre: str = Field(min_length=3, max_length=100)
    grupo_muscular: GrupoMuscular
    series: int = Field(ge=1, le=10)
    repeticiones: int = Field(ge=1, le=50)
    nivel: Nivel
    activa: bool = True


class RutinaOut(RutinaIn):
    model_config = ConfigDict(from_attributes=True)
    id: int


# --------------------------------------------------------------- Autenticación
bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def crear_token(user_id: int) -> str:
    expira = datetime.now(timezone.utc) + timedelta(hours=TOKEN_HORAS)
    return jwt.encode({"sub": str(user_id), "exp": expira}, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    db: Session = Depends(get_db),
) -> Usuario:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Falta el token de sesión")
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido o expirado")
    user = db.get(Usuario, user_id)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Usuario no encontrado")
    return user


# ------------------------------------------------------------------------- App
app = FastAPI(title="GymApp API")


@app.post("/register", response_model=AuthOut, status_code=status.HTTP_201_CREATED)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    correo = data.correo.lower()
    if db.scalar(select(Usuario).where(Usuario.correo == correo)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Ese correo ya está registrado")
    user = Usuario(nombre=data.nombre, correo=correo, password_hash=hash_password(data.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return AuthOut(token=crear_token(user.id), user=user)


@app.post("/login", response_model=AuthOut)
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = db.scalar(select(Usuario).where(Usuario.correo == data.correo.lower()))
    if user is None or not check_password(data.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Correo o contraseña incorrectos")
    return AuthOut(token=crear_token(user.id), user=user)


def _rutina_o_404(db: Session, rutina_id: int, user: Usuario) -> Rutina:
    rutina = db.scalar(select(Rutina).where(Rutina.id == rutina_id, Rutina.usuario_id == user.id))
    if rutina is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rutina no encontrada")
    return rutina


@app.get("/rutinas", response_model=list[RutinaOut])
def listar(db: Session = Depends(get_db), user: Usuario = Depends(get_current_user)):
    return db.scalars(
        select(Rutina).where(Rutina.usuario_id == user.id).order_by(Rutina.id.desc())
    ).all()


@app.get("/rutinas/{rutina_id}", response_model=RutinaOut)
def obtener(rutina_id: int, db: Session = Depends(get_db), user: Usuario = Depends(get_current_user)):
    return _rutina_o_404(db, rutina_id, user)


@app.post("/rutinas", response_model=RutinaOut, status_code=status.HTTP_201_CREATED)
def crear(data: RutinaIn, db: Session = Depends(get_db), user: Usuario = Depends(get_current_user)):
    rutina = Rutina(**data.model_dump(), usuario_id=user.id)
    db.add(rutina)
    db.commit()
    db.refresh(rutina)
    return rutina


@app.put("/rutinas/{rutina_id}", response_model=RutinaOut)
def actualizar(
    rutina_id: int,
    data: RutinaIn,
    db: Session = Depends(get_db),
    user: Usuario = Depends(get_current_user),
):
    rutina = _rutina_o_404(db, rutina_id, user)
    for campo, valor in data.model_dump().items():
        setattr(rutina, campo, valor)
    db.commit()
    db.refresh(rutina)
    return rutina


@app.delete("/rutinas/{rutina_id}", status_code=status.HTTP_204_NO_CONTENT)
def eliminar(rutina_id: int, db: Session = Depends(get_db), user: Usuario = Depends(get_current_user)):
    rutina = _rutina_o_404(db, rutina_id, user)
    db.delete(rutina)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
