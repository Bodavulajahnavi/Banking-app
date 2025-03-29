from flask import Flask
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv(os.path.join(os.path.dirname(__file__), '../../.env'))

from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from datetime import timedelta
from backend.auth import register_user, login, logout, protected

app = Flask(__name__)

# Security configurations
app.config.update({
    'JWT_SECRET_KEY': os.getenv('JWT_SECRET') or os.urandom(32),
    'JWT_ACCESS_TOKEN_EXPIRES': timedelta(minutes=15),
    'PERMANENT_SESSION_LIFETIME': timedelta(minutes=30),
    'SESSION_COOKIE_SECURE': True,
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'MAX_CONTENT_LENGTH': 16 * 1024 * 1024  # 16MB limit
})

# Initialize security extensions
jwt = JWTManager(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://"
)
Talisman(app,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    frame_options='DENY',
    content_security_policy={
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'"],
        'style-src': ["'self'", "'unsafe-inline'"],
    }
)

# Register routes
app.route('/register', methods=['POST'])(register_user)
app.route('/login', methods=['POST'])(login)
app.route('/logout', methods=['POST'])(logout)
app.route('/protected', methods=['GET'])(protected)

@app.route('/')
@limiter.limit("10 per minute")
def health_check():
    return {'status': 'healthy', 'security': 'enabled'}

if __name__ == '__main__':
    app.run(
        ssl_context=(
            '/project/sandbox/user-workspace/banking-app/cert.pem',
            '/project/sandbox/user-workspace/banking-app/key.pem'
        ),
        host='0.0.0.0',
        port=8000
    )