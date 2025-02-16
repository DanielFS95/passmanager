from flask import Flask, request
import os
import logging
from project.two_factor_auth import tfa_bp
from project.user import user_bp
from project.auth import auth_bp
from project.common import init_limiter


app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
app.config["SECRET_KEY"] = os.urandom(24)
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
init_limiter(app)


@app.before_request
def log_request():
    request_data = request.get_json(silent=True)  # Capture JSON body (if any)
    logging.info(f"📥 Incoming request: {request.method} {request.path} | IP: {request.remote_addr} | Data: {request_data}")

@app.after_request
def log_response(response):
    logging.info(f"📤 Response: {response.status_code}")
    return response

app.register_blueprint(user_bp, url_prefix='/user')
app.register_blueprint(tfa_bp, url_prefix='/tfa')
app.register_blueprint(auth_bp, url_prefix='/account')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
