"""
Database connection and session management.
Uses SQLAlchemy with SQLite for lightweight deployment.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from database.models import Base

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database/iot_secure.db")

# SQLite-specific: check_same_thread=False required for FastAPI's async nature
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """
    FastAPI dependency that yields a database session.
    Ensures the session is properly closed after each request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
