import mariadb
from password_validator import PasswordValidator
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import logging
from dopplersdk import DopplerSDK


logging.basicConfig(level=logging.DEBUG)
load_dotenv()
doppler = DopplerSDK()
doppler.set_access_token(os.getenv("DOPPLER_TOKEN"))


limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["500 per day", "60 per hour"],
    strategy="fixed-window"
)


def init_limiter(app):
    limiter.init_app(app)


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


pool = None


# Connection pool. To speed up the process of checking database.
def get_connection_pool():
    global pool
    if pool is None:
        logging.debug("Initializing MariaDB connection pool...")
        user = get_doppler_secrets("MARIADB_USER")
        password = get_doppler_secrets("MARIADB_PASS")
        host = get_doppler_secrets("MARIADB_HOST")
        port = int(get_doppler_secrets("MARIADB_PORT"))
        database = get_doppler_secrets("MARIADB_DATABASE")

        # Log the retrieved secrets to ensure they are not None
        logging.debug(f"User: {user}, Host: {host}, Port: {port}, Database: {database}")

        if not all([user, password, host, database]):
            raise ValueError("Failed to retrieve database credentials from Doppler")

        pool = mariadb.ConnectionPool(
            user=user,
            password=password,
            host=host,
            port=port,
            database=database,
            pool_name="mypool",
            pool_size=5
        )
    return pool
