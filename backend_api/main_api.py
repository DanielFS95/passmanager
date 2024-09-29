from flask import Flask, current_app
import os
from .project.two_factor_auth import tfa_bp
from .project.user import user_bp
from .project.auth import auth_bp

from .project.common import limiter


app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
app.config["SECRET_KEY"] = os.urandom(24)
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

with app.app_context():
    limiter = limiter()

app.register_blueprint(user_bp, url_prefix='/user')
app.register_blueprint(tfa_bp, url_prefix='/tfa')
app.register_blueprint(auth_bp, url_prefix='/account')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
