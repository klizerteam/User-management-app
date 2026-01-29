from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Literal, List

from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session
# DATABASE CONFIG
DATABASE_URL = "postgresql://postgres:Nourin123@localhost:5432/user_management"

engine = create_engine(DATABASE_URL) 
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False) 
Base = declarative_base() 
# ORM MODEL (Database Table)
class UserDB(Base): # Database model for user data
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    role = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
# Create tables
Base.metadata.create_all(bind=engine) # Create the users table in the database
# Pydantic SCHEMAS
class UserCreate(BaseModel): # Schema for creating/updating user data
    name: str
    email: EmailStr
    role: Literal["admin", "user"]
class UserResponse(UserCreate): # Schema for responding with user data
    id: int
    created_at: datetime

    class Config:
        from_attributes = True
# FASTAPI APP
app = FastAPI()
app.add_middleware( # Add CORS middleware
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)
# DATABASE DEPENDENCY
def get_db():
    db = SessionLocal() # Create a new database session
    try:
        yield db
    finally:
        db.close()
# API ENDPOINTS
# CREATE USER
@app.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED) # Create a new user
def create_user(user: UserCreate, db: Session = Depends(get_db)):

    existing_user = db.query(UserDB).filter(UserDB.email == user.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already exists"
        )

    new_user = UserDB(
        name=user.name,
        email=user.email,
        role=user.role
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user
# GET ALL USERS
@app.get("/users", response_model=List[UserResponse]) # Retrieve all users
def get_users(db: Session = Depends(get_db)):
    return db.query(UserDB).all()
# GET USER BY ID
@app.get("/users/{user_id}", response_model=UserResponse) # Retrieve a user by ID
def get_user(user_id: int, db: Session = Depends(get_db)):

    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return user
# UPDATE USER
@app.put("/users/{user_id}", response_model=UserResponse) # Update a user by ID
def update_user(
    user_id: int,
    updated: UserCreate,
    db: Session = Depends(get_db)
):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user.name = updated.name
    user.email = updated.email
    user.role = updated.role

    db.commit()
    db.refresh(user)

    return user
# DELETE USER
@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT) # Delete a user by ID
def delete_user(user_id: int, db: Session = Depends(get_db)):

    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    db.delete(user)
    db.commit()
    return
