from flask import Blueprint
import mariadb
import logging
import json
import os
from flask import request, jsonify, session
import ulid
from project.common import limiter, mariadb_connection_pool, redis_connection_pool, debug_db_connection
from project.auth_tools import check_pass, get_user_id_with_session_token, check_session, update_session, pass_encrypt, pass_decrypt, hibp_password_leak
from project.two_factor_auth import tfa_check, validate_tfa


user_bp = Blueprint('user', __name__)

def get_mariadb_pool():
    global mariadb_pool
    if mariadb_pool is None:
        mariadb_pool = mariadb_connection_pool()
    return mariadb_pool


def get_redis_pool():
    global redis_client
    if redis_client is None:
        redis_client = redis_connection_pool()
    return redis_client


# Used for adding a new service to the password manager for a specfic account.
@user_bp.route("/services/add", methods=["POST"])
@limiter.limit("100/hour")
def add_service():
    debug_db_connection()
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout": "Session timeout!"}), 440
    data = request.get_json()
    if not data:
        return jsonify({"error":"Data error"}), 403
    update_session(session_token, user_id)
    try:
        service = data.get("service")
        username = data.get("username")
        password = data.get("password")
        id = ulid.new().str

        if not all([service, username, password, id]):
            return (jsonify({"error": "Data error"}), 406)

        encryption_key = bytes.fromhex(os.getenv("ENCRYPTION_KEY"))
        encrypt_pass = pass_encrypt(encryption_key, password)
        password_leak_amount = hibp_password_leak(password)

        with get_mariadb_pool().get_connection() as conn:
            with conn.cursor() as cursor:
                if data.get("already_exist"):
                    cursor.execute(
                        "UPDATE user_info SET password = %s, password_leak_amount = %s WHERE username = %s "
                        "AND service = %s AND user_id = %s", (encrypt_pass, password_leak_amount, username, service, user_id)
                    )
                    conn.commit()

                    result_message = {"pass_overwritten":"completed"}
                else:
                    cursor.execute(
                        "INSERT INTO user_info (ulid, user_id, password_leak_amount, service, password, username)"
                        "VALUES (%s, %s, %s, %s, %s, %s)", (id, user_id, password_leak_amount, service, encrypt_pass, username)
                    )
                    conn.commit()
                    result_message = {"status":"Account added sucessfully"}

        redis_client = get_redis_pool()
        if redis_client:
            cache_key = f"{user_id}:services"
            for key in redis_client.scan_iter(cache_key):
                redis_client.delete(key)

        return jsonify(result_message), 200

    except mariadb.Error:
        return jsonify({"error": "Internal Server Error"}), 500


# Used when the service is listed only once. Deletes using only service and user_id.
@user_bp.route("/services/remove", methods=["DELETE"])
@limiter.limit("100/hour")
def remove_service():
    debug_db_connection()
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout": "Session timeout!"}), 440
    data = request.get_json()
    if not data:
        return jsonify({"error": "Der er ingen data at hente"}), 400
    update_session(session_token, user_id)

    service = data.get("service")
    username = data.get("account")

    if not service:
        return (jsonify({"error": "Der mangler en eller flere af de påkrævede felter"}), 400)

    try:
        with get_mariadb_pool().get_connection() as conn:
            with conn.cursor() as cursor:
                if username:
                    cursor.execute("DELETE FROM user_info WHERE service = %s AND username = %s AND user_id = %s", (service, username, user_id),)
                    result_message = {"status": "data-deletion succes"}

                else:
                    cursor.execute("DELETE FROM user_info WHERE service = %s AND user_id = %s", (service, user_id),)
                    result_message = {"status": "data-deletion succes"}

                if cursor.rowcount == 0:
                    return jsonify({"error": "Service-navnet findes ikke!"}), 404

                conn.commit()

        redis_client = get_redis_pool()
        if redis_client:
            cache_key = f"{user_id}:services"
            for key in redis_client.scan_iter(cache_key):
                redis_client.delete(key)

            return jsonify(result_message), 200

    except mariadb.Error as e:
        return jsonify({"error": "Internal Server Error"}), 500


# Checks if a username is already in the database. Makes sure that each user that is created is unique.
@user_bp.route("/username/availability", methods=["GET"])
@limiter.limit("100/hour")
def check_username():
    debug_db_connection()
    username = request.args.get("username").strip().lower()
    if not username:
        return jsonify({"error":"Missing username"}), 400
    try:
        with get_mariadb_pool().get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1 FROM pm_users WHERE username = %s", (username,))
                if cursor.fetchone() is None:
                    return jsonify({"available": True}), 200
                else:
                    return jsonify({"available": False}), 409
    except mariadb.Error as e:
        return jsonify({"error": "Internal Server Error"}), 500


# Retrieves password when the service is only listed once. Retrieves using only service and user_id.
@user_bp.route("/services/retrieve", methods=["GET"])
@limiter.limit("100/hour")
def password_retriever():
    debug_db_connection()
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout": "Session timeout!"}), 440
    update_session(session_token, user_id)

    data = request.get_json()
    service = data.get("service")
    username = data.get("account")

    if not service:
        return (jsonify({"error": "Der mangler en eller flere af de påkrævede felter"}), 400)
    

    try:
        with get_mariadb_pool().get_connection() as conn:
            with conn.cursor() as cursor:
                if username:
                    cursor.execute(
                        "SELECT username, password, password_leak_amount FROM user_info WHERE service = %s "
                        "AND username = %s AND user_id = %s", (service, username, user_id)
                    )

                else:
                    cursor.execute("SELECT username, password, password_leak_amount FROM user_info WHERE service = %s AND user_id = %s", (service, user_id))

                retrieved_info = cursor.fetchone()

                if retrieved_info:
                    username, encrypted_password, password_leak_amount = retrieved_info
                    encryption_key = bytes.fromhex(os.getenv("ENCRYPTION_KEY"))
                    decrypted_password = pass_decrypt(encryption_key, encrypted_password)
                    if password_leak_amount is not None:
                        return (jsonify({"username": username, "password": decrypted_password, "password_leak_amount": password_leak_amount}), 200)
                    return (jsonify({"username": username, "password": decrypted_password}), 200)
                else:
                    return (jsonify({"error": "Service-navnet blev ikke fundet."}), 404)

    except mariadb.Error:
        return jsonify({"error": "Internal Server Error"}), 500


@user_bp.route("/accountdelete", methods=["POST"])
@limiter.limit("25/hour")
def delete_account():
    debug_db_connection()
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout": "Session timeout!"}), 440

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    tfa_code = data.get("tfa_code")

    redis_client = get_redis_pool()
    tfa_pending_key = f"{user_id}:tfa_pending"


    if tfa_code:

        if not redis_client.get(tfa_pending_key):
            return jsonify({"error": "Invalid or expired request"}), 401
        redis_client.delete(tfa_pending_key)

        if not validate_tfa(tfa_code, username, user_id):
            return jsonify({"error": "Invalid TFA code"}), 401


    else:

        if not check_pass(password, username):
            return jsonify({"error": "Unauthorized"}), 401

        if tfa_check(username, user_id):
            redis_client.setex(tfa_pending_key, 300, "pending") 
            return jsonify({"tfa_confirm": "tfa_confirm", "username": username}), 200
        

    try:
        with get_mariadb_pool().get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM user_info WHERE user_id = %s", (user_id,))
                cursor.execute("DELETE FROM pm_users WHERE user_id = %s", (user_id,))
                cursor.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
                conn.commit()
                
                session.clear()
                response = jsonify({"delete_complete": "delete_complete"})
                response.set_cookie("session_token", "", expires=0)

                return response
    except mariadb.Error:
        return jsonify({"error": "Internal Server Error"}), 500


# Is used to provide a list of the services a specific has stored in the manager already.
@user_bp.route("/services/servicelist", methods=["GET"])
@limiter.limit("1000/hour")
def showlist():
    debug_db_connection()
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout": "Session timeout!"}), 440
    

    redis_client = get_redis_pool()
    cache_key = f"{user_id}:services"
    cached_services = redis_client.get(cache_key)
    if cached_services:
        logging.debug(f"Cache hit: Retrieved data for user {user_id} from Redis")
        return jsonify({"services": json.loads(cached_services)}), 200
    logging.debug(f"Cache miss: Querying MariaDB for user {user_id}")


    try:
        with get_mariadb_pool().get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT service, username, password_leak_amount FROM user_info WHERE user_id = %s ORDER BY service, username, password_leak_amount", (user_id,)
                )
                retrieved_info = cursor.fetchall()
                services_dict = {}
                for service, username, password_leak_amount in retrieved_info:
                    if service not in services_dict:
                        services_dict[service] = []
                    services_dict[service].append({
                        "username": username,
                        "password_leak_amount": password_leak_amount
                    })


                redis_client.setex(cache_key, 600, json.dumps(services_dict))
                logging.debug(f"Data stored in Redis cache for user {user_id}")


                return jsonify({"services": services_dict}), 200


    except mariadb.Error as e:
        return jsonify({"error": "Internal Server Error"}), 500
