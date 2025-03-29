from sqlalchemy import create_engine, Column, Integer, String, DateTime, Numeric, Boolean, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import bcrypt
from cryptography.fernet import Fernet
import os

Base = declarative_base()

# Generate encryption key if not exists
def get_encryption_key():
    key = os.getenv('ENCRYPTION_KEY')
    if not key:
        raise ValueError("ENCRYPTION_KEY not set in environment")
    return key.encode()

fernet = Fernet(get_encryption_key())

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(60), nullable=False)
    email = Column(LargeBinary, nullable=False)  # Encrypted
    phone = Column(LargeBinary)  # Encrypted
    is_verified = Column(Boolean, default=False)
    last_login = Column(DateTime)
    failed_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    mfa_secret = Column(LargeBinary)  # Encrypted
    
    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def encrypt_field(self, data):
        return fernet.encrypt(data.encode('utf-8'))
    
    def decrypt_field(self, encrypted_data):
        return fernet.decrypt(encrypted_data).decode('utf-8')

class Account(Base):
    __tablename__ = 'accounts'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    account_number = Column(String(20), unique=True, nullable=False)
    balance = Column(Numeric(15, 2), default=0.00)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_activity = Column(DateTime)

class Transaction(Base):
    __tablename__ = 'transactions'
    
    id = Column(Integer, primary_key=True)
    from_account = Column(String(20), nullable=False)
    to_account = Column(String(20), nullable=False)
    amount = Column(Numeric(15, 2), nullable=False)
    description = Column(LargeBinary)  # Encrypted
    status = Column(String(20), default='pending')
    risk_score = Column(Numeric(5, 2))
    created_at = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String(45))
    device_fingerprint = Column(String(100))
    location_data = Column(LargeBinary)  # Encrypted

# Initialize database with connection pooling
engine = create_engine(
    'sqlite:////project/sandbox/user-workspace/banking-app/data/banking.db',
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=3600
)

# Create tables only if they don't exist
try:
    Base.metadata.create_all(engine)
except sqlalchemy.exc.OperationalError as e:
    if "already exists" not in str(e):
        raise

Session = sessionmaker(bind=engine)
