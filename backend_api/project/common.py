import mariadb
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import threading
import redis

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["500 per day", "60 per hour"],
    strategy="fixed-window"
)


def init_limiter(app):
    limiter.init_app(app)


mariadb_pool = None
redis_client = None
redis_lock = threading.Lock()
mariadb_lock = threading.Lock()
active_db_connections = threading.local()


def redis_connection_pool():
    global redis_client
    if redis_client is None:
        with redis_lock:
            if redis_client is None:
                try:
                    redis_pool = redis.ConnectionPool(
                        host=os.getenv("REDIS_HOST"),
                        port=int(os.getenv("REDIS_PORT")),
                        password=os.getenv("REDIS_PASSWORD"),
                        max_connections=10,
                        decode_responses=True,
                    )
                    redis_client = redis.Redis(connection_pool=redis_pool)
                except redis.ConnectionError as e:
                    logging.critical("Connection error while connecting to Redis: %s", e)
                    return None
                except Exception as e:
                    logging.error("There was an error during the initialization of the Redis connection pool: %s", e)
                    return None
                
    return redis_client


def get_redis_pool():
    global redis_client
    if redis_client is None:
        redis_client = redis_connection_pool()
    return redis_client


# Connection mariadb_pool. To speed up the process of checking database.
def mariadb_connection_pool():
    global mariadb_pool
    if mariadb_pool is None:
        with mariadb_lock:
            if mariadb_pool is None:
                try:
                    mariadb_pool = mariadb.ConnectionPool(
                        user=os.getenv("MARIADB_USER"),
                        password=os.getenv("MARIADB_PASS"),
                        host=os.getenv("MARIADB_HOST"),
                        port=int(os.getenv("MARIADB_PORT")),
                        database=os.getenv("MARIADB_DATABASE"),
                        pool_name="mariadb_pool",
                        pool_size=50
                    )
                except mariadb.Error as e:
                    logging.critical(f"MariaDB connection pool error: {e}")
                    return None
    return mariadb_pool


def get_mariadb_pool():
    global mariadb_pool
    if mariadb_pool is None:
        mariadb_pool = mariadb_connection_pool()
    return mariadb_pool