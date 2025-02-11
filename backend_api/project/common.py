import mariadb
from password_validator import PasswordValidator
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import logging
import threading
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
#def get_doppler_secrets(secret_name):
    #secrets = doppler.secrets.get(project="docker", config="dev", name=secret_name)
    #values = secrets.value
    #if isinstance(values, dict):
        #return values.get("raw")


pool = None
pool_lock = threading.Lock()


# Connection pool. To speed up the process of checking database.
def get_connection_pool():
    global pool
    if pool is None:
        with pool_lock:
            if pool is None:
                try:
                    logging.debug("Attempting to initialize MariaDB connection pool...")
                    pool = mariadb.ConnectionPool(
                        user=os.getenv("$MARIADB_USER"),
                        password=os.getenv("MARIADB_PASS"),
                        host=os.getenv("MARIADB_HOST"),
                        port=int(os.getenv("MARIADB_PORT")),
                        database=os.getenv("MARIADB_DATABASE"),
                        pool_name="mypool",
                        pool_size=5
                    )
                    logging.debug("Connection pool initialized successfully.")
                except mariadb.OperationalError as e:
                    logging.critical("Operational error while connecting to the database"), e
                    return None
                except mariadb.InterfaceError as e:
                    logging.error("There was an error with the interface"), e
                    return None
                except Exception as e:
                    logging.error("There was an error during the initialization of the database"), e
                    return None
    return pool
