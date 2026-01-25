# dagster_authkit/auth/manager.py

import logging
import secrets
import string
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dagster_authkit.utils.config import config
from dagster_authkit.auth.models import Base, User
from dagster_authkit.auth.security import SecurityHardening

logger = logging.getLogger(__name__)

DB_URL = config.DB_URL
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(bind=engine)

def bootstrap_db():
    """
    Ensures tables exist and creates an admin user if the database is empty.
    Returns the generated password on first run.
    """
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        # Check if users already exist
        if db.query(User).count() > 0:
            return None

        # Generate a secure random password
        alphabet = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(alphabet) for _ in range(16))
        
        # Create initial admin user
        admin = User(
            username="admin",
            roles=["admin", "editor", "viewer"]
        )
        # Use the security utility to hash the password
        admin.password_hash = SecurityHardening.hash_password(password)
        
        db.add(admin)
        db.commit()
        
        logger.info("Successfully bootstrapped database with admin user.")
        return password
    except Exception as e:
        logger.error(f"Database bootstrap failed: {e}")
        return None
    finally:
        db.close()