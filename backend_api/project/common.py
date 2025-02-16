import mariadb
from password_validator import PasswordValidator
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import threading
import redis


logging.basicConfig(level=logging.DEBUG)

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


mariadb_pool = None
redis_client = None
redis_lock = threading.Lock()
mariadb_lock = threading.Lock()


def redis_connection_pool():
    global redis_client
    if redis_client is None:
        with redis_lock:
            if redis_client is None:
                try:
                    logging.debug("Attempting to initialize Redis connection pool...")
                    redis_pool = redis.ConnectionPool(
                        host=os.getenv("REDIS_HOST", "localhost"),
                        port=int(os.getenv("REDIS_PORT", 6379)),
                        password=os.getenv("REDIS_PASSWORD"),
                        max_connections=10,
                        decode_responses=True,
                    )
                    redis_client = redis.Redis(connection_pool=redis_pool)
                    logging.debug("Redis connection pool initialized successfully.")
                except redis.ConnectionError as e:
                    logging.critical("Connection error while connecting to Redis: %s", e)
                    return None
                except Exception as e:
                    logging.error("There was an error during the initialization of the Redis connection pool: %s", e)
                    return None
                
    return redis_client


# Connection mariadb_pool. To speed up the process of checking database.
def mariadb_connection_pool():
    global mariadb_pool
    if mariadb_pool is None:
        with mariadb_lock:
            if mariadb_pool is None:
                try:
                    logging.debug("Attempting to initialize MariaDB connection mariadb_pool...")
                    mariadb_pool = mariadb.ConnectionPool(
                        user=os.getenv("MARIADB_USER"),
                        password=os.getenv("MARIADB_PASS"),
                        host=os.getenv("MARIADB_HOST"),
                        port=int(os.getenv("MARIADB_PORT")),
                        database=os.getenv("MARIADB_DATABASE"),
                        pool_name="mariadb_pool",
                        pool_size=5
                    )
                    logging.debug("Connection mariadb_pool initialized successfully.")
                except mariadb.OperationalError as e:
                    logging.critical(f"Operational error while connecting to the database: {e}")
                    return None
                except mariadb.InterfaceError as e:
                    logging.error(f"There was an error with the interface: {e}")
                    return None
                except Exception as e:
                    logging.error(f"There was an error during the initialization of the database: {e}")
                    return None
                
    return mariadb_pool
