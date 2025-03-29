#!/bin/bash

# Verify running as non-root
if [ "$(id -u)" -eq 0 ]; then
    echo "Error: Do not run as root"
    exit 1
fi

# Load environment variables
set -a
source .env
set +a

# Verify required environment variables
if [ -z "$ENCRYPTION_KEY" ]; then
    echo "Error: ENCRYPTION_KEY not set in .env"
    exit 1
fi

# Run security checks
echo "Running security checks..."
bandit -r backend/
safety check

# Start the application
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