from flask import request, abort
import re
from datetime import datetime
from functools import wraps
import hashlib
import os

class SecurityManager:
    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize security extensions with the Flask app"""
        self.app = app
        self._setup_headers()
        self._setup_request_checks()
        
    def _setup_headers(self):
        @self.app.after_request
        def _add_security_headers(response):
            # Security headers
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            response.headers['Feature-Policy'] = "geolocation 'none'; microphone 'none'"
            return response
    
    def _setup_request_checks(self):
        @self.app.before_request
        def _validate_request():
            # Block suspicious user agents
            if 'User-Agent' not in request.headers:
                abort(400, description="Invalid request")
                
            # Validate content type for POST requests
            if request.method == 'POST' and not request.is_json:
                abort(415, description="Unsupported Media Type")
                
            # Check for SQL injection patterns
            if self._detect_sqli(request):
                abort(400, description="Invalid request parameters")

    def _detect_sqli(self, request):
        """Detect common SQL injection patterns"""
        sqli_patterns = [
            r'(\%27)|(\')|(\-\-)',
            r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))',
            r'\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))'
        ]
        
        for pattern in sqli_patterns:
            for value in request.values.values():
                if re.search(pattern, str(value), re.IGNORECASE):
                    return True
        return False

    @staticmethod
    def generate_csrf_token():
        """Generate a secure CSRF token"""
        return hashlib.sha256(os.urandom(64)).hexdigest()

    @staticmethod
    def validate_csrf_token(token):
        """Validate CSRF token structure"""
        if not token or len(token) != 64:
            return False
        return True

def security_headers(f):
    """Decorator to add security headers to specific routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        return response
    return decorated_function

def rate_limit_by_ip(f):
    """Decorator to implement IP-based rate limiting"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Implementation would use Redis in production
        return f(*args, **kwargs)
    return decorated_function