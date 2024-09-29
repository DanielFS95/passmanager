import mariadb
from flask import current_app
from password_validator import PasswordValidator
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from dopplersdk import DopplerSDK

load_dotenv()
doppler = DopplerSDK()
doppler.set_access_token(os.getenv("DOPPLER_TOKEN"))


def limiter():
    limiter = Limiter(
        key_func=get_remote_address,
        app=current_app,
        default_limits=["500 per day", "60 per hour"],
        strategy="fixed-window"
    )
    return limiter


validatepass = PasswordValidator()
validatepass\
    .min(10)\
    .has().uppercase()\
    .has().lowercase()\
    .has().digits()\
    .no().spaces()


# Retrieving doppler secrets
def get_doppler_secrets(secret_name):
    secrets = doppler.secrets.get(project="docker", config="dev", name=secret_name)
    values = secrets.value
    if isinstance(values, dict):
        return values.get("raw")


# Connection pool. To speed up the process of checking database.
pool = mariadb.ConnectionPool(
    user=get_doppler_secrets("MARIADB_USER"),
    password=get_doppler_secrets("MARIADB_PASS"),
    host=get_doppler_secrets("MARIADB_HOST"),
    port=int(get_doppler_secrets("MARIADB_PORT")),
    database=get_doppler_secrets("MARIADB_DATABASE"),
    pool_name="mypool",
    pool_size=5,)
