from flask import request, jsonify

def add_security_headers(app):
    @app.after_request
    def security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Feature-Policy'] = "geolocation 'none'; microphone 'none'"
        return response

def validate_request():
    """Validate incoming requests for security"""
    if 'User-Agent' not in request.headers:
        return jsonify({"error": "Invalid request"}), 400

    if request.method == 'POST' and not request.is_json:
        return jsonify({"error": "Unsupported Media Type"}), 415

    return None