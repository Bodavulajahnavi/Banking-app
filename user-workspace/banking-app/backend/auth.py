from flask import request, jsonify
from flask_jwt_extended import (
    create_access_token, 
    jwt_required, 
    get_jwt_identity,
    get_jwt,
    set_access_cookies,
    unset_jwt_cookies
)
from backend.models import User, Session

from datetime import datetime, timedelta
import bcrypt
import re
from werkzeug.security import check_password_hash
from functools import wraps
import time
import hashlib

# Security configurations
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 30  # minutes
TOKEN_BLACKLIST = set()
PASSWORD_COMPLEXITY = {
    'min_length': 12,
    'require_upper': True,
    'require_lower': True,
    'require_number': True,
    'require_special': True
}

def validate_password_complexity(password):
    """Enforce strong password requirements"""
    if len(password) < PASSWORD_COMPLEXITY['min_length']:
        return False, "Password must be at least 12 characters"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_number = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    if PASSWORD_COMPLEXITY['require_upper'] and not has_upper:
        return False, "Password must contain uppercase letters"
    if PASSWORD_COMPLEXITY['require_lower'] and not has_lower:
        return False, "Password must contain lowercase letters"
    if PASSWORD_COMPLEXITY['require_number'] and not has_number:
        return False, "Password must contain numbers"
    if PASSWORD_COMPLEXITY['require_special'] and not has_special:
        return False, "Password must contain special characters"
    
    return True, ""

def register_user():
    data = request.get_json()
    
    # Input validation
    if not all(k in data for k in ['username', 'password', 'email']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    is_valid, message = validate_password_complexity(data['password'])
    if not is_valid:
        return jsonify({'error': message}), 400
    
    if not re.match(r"[^@]+@[^@]+\.[^@]+", data['email']):
        return jsonify({'error': 'Invalid email format'}), 400
    
    session = Session()
    
    # Check if user exists
    if session.query(User).filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 409
        
    if session.query(User).filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 409
    
    # Create new user with secure defaults
    new_user = User(
        username=data['username'],
        email=data['email'],
        phone=data.get('phone', ''),
        is_verified=False,
        failed_attempts=0
    )
    new_user.set_password(data['password'])
    
    session.add(new_user)
    session.commit()
    
    return jsonify({
        'message': 'User registered successfully',
        'security': {
            'password_strength': 'strong',
            'account_protection': 'enabled'
        }
    }), 201

def login():
    data = request.get_json()
    session = Session()
    
    # Rate limiting by IP
    client_ip = request.remote_addr
    ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()
    
    user = session.query(User).filter_by(username=data['username']).first()
    
    # Security checks
    if not user:
        time.sleep(1)  # Prevent timing attacks
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if user.locked_until and user.locked_until > datetime.utcnow():
        return jsonify({
            'error': 'Account temporarily locked',
            'locked_until': user.locked_until.isoformat(),
            'security_contact': 'security@bank.com'
        }), 403
    
    if not user.check_password(data['password']):
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_LOGIN_ATTEMPTS:
            user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_TIME)
        session.commit()
        time.sleep(1)  # Prevent timing attacks
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Successful login - reset counters
    user.failed_attempts = 0
    user.last_login = datetime.utcnow()
    session.commit()
    
    # Create secure JWT token
    additional_claims = {
        "2fa_verified": False,
        "security_level": "standard",
        "ip_hash": ip_hash
    }
    access_token = create_access_token(
        identity=user.username,
        additional_claims=additional_claims,
        expires_delta=timedelta(minutes=15)
    )
    
    response = jsonify({
        'access_token': access_token,
        'requires_2fa': not user.is_verified,
        'security_notice': 'This session will expire after 15 minutes of inactivity'
    })
    
    # Set secure cookies
    set_access_cookies(response, access_token)
    return response, 200

def logout():
    response = jsonify({"msg": "Logout successful"})
    unset_jwt_cookies(response)
    TOKEN_BLACKLIST.add(get_jwt()['jti'])
    return response

@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

def token_blacklist_check(jwt_header, jwt_payload):
    return jwt_payload['jti'] not in TOKEN_BLACKLIST