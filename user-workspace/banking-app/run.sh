#!/bin/bash

# Security checks before running
if [ "$(id -u)" -eq 0 ]; then
    echo "Error: Do not run as root"
    exit 1
fi

if [ ! -f ".env" ]; then
    echo "Creating .env file with security defaults..."
    cat > .env <<EOL
# Security Configuration
ENCRYPTION_KEY=$(openssl rand -base64 32)
JWT_SECRET=$(openssl rand -base64 32)
SESSION_SECRET=$(openssl rand -base64 32)
DB_PASSWORD=$(openssl rand -base64 16)

# Security Headers
CSP_DEFAULT_SRC="'self'"
CSP_SCRIPT_SRC="'self' 'unsafe-inline'"
CSP_STYLE_SRC="'self' 'unsafe-inline'"
CSP_IMG_SRC="'self' data:"
EOL
    chmod 600 .env
fi

# Install dependencies in secure environment
pip install --require-hashes -r requirements.txt

# Initialize database
python -c "
from backend.models import Base, engine
Base.metadata.create_all(engine)
print('Database initialized with security constraints')
"

# Run security checks
echo "Running security checks..."
bandit -r backend/
safety check

# Load environment variables
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
    echo "Environment variables loaded from .env"
else
    echo "Error: .env file not found"
    exit 1
fi

# Start the application with security features
echo "Starting secure banking application..."

gunicorn --bind 0.0.0.0:8000 \
    --workers 4 \
    --threads 2 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile - \
    --certfile=cert.pem \
    --keyfile=key.pem \
    --limit-request-line 8190 \
    backend.app:app