from sqlalchemy import Column, String, JSON
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = "auth_users"
    username = Column(String(255), primary_key=True)
    password_hash = Column(String(255), nullable=False)
    roles = Column(JSON, nullable=False)