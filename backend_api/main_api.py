from flask import Flask, request
import os
import logging
from project.two_factor_auth import tfa_bp
from project.service_endpoints import user_bp
from project.auth_endpoints import auth_bp
from project.common import init_limiter


app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
app.config["SECRET_KEY"] = os.urandom(24)
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
init_limiter(app)

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger("werkzeug").setLevel(logging.WARNING)


@app.before_request
def log_request():
    request_data = request.get_json(silent=True) or {}  # Capture JSON body (if any)
    username = request.cookies.get("username", "Anonymous")
    if username == "Anonymous":
        username = request_data.get("username", "Anonymous")
    logging.info(f"Incoming request: {request.method} {request.path} | Username: {username}")


@app.after_request
def log_response(response):
    logging.info(f"Response: {response.status_code}")
    return response

app.register_blueprint(user_bp, url_prefix='/user')
app.register_blueprint(tfa_bp, url_prefix='/tfa')
app.register_blueprint(auth_bp, url_prefix='/account')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
