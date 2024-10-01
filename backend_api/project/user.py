from flask import Blueprint
import mariadb
from flask import request, jsonify, session
import ulid
from project.common import limiter, get_connection_pool, get_doppler_secrets
from project.auth_tools import check_pass, get_user_id_with_session_token, check_session, update_session, pass_encrypt, pass_decrypt
from project.two_factor_auth import tfa_check, validate_tfa


user_bp = Blueprint('user', __name__)

pool = get_connection_pool()


# Used for adding a new service to the password manager for a specfic account.
@user_bp.route("/services/add", methods=["POST"])
@limiter.limit("100/hour")
def add_service():
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout": "Session timeout!"}), 440
    data = request.get_json()
    if not data:
        return jsonify({"error": "Der er ingen data at hente"}), 403
    update_session(session_token, user_id)
    try:
        service = data.get("service")
        username = data.get("username")
        password = data.get("password")

        id = ulid.new().str

        if not all([service, username, password, id]):
            return (jsonify({"error": "Der mangler en eller flere af de påkrævede felter"}), 406)

        encryption_key = bytes.fromhex(get_doppler_secrets("ENCRYPTION_KEY"))
        encrypt_pass = pass_encrypt(encryption_key, password)

        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                if data.get("already_exist"):
                    cursor.execute(
                        "UPDATE user_info SET password = %s WHERE username = %s "
                        "AND service = %s AND user_id = %s", (encrypt_pass, username, service, user_id)
                    )
                    conn.commit()
                    return (jsonify({"pass_overwritten": "completed"})), 200
                else:
                    cursor.execute(
                        "INSERT INTO user_info (ulid, user_id, service, password, username)"
                        "VALUES (%s, %s, %s, %s, %s)", (id, user_id, service, encrypt_pass, username)
                    )
                    conn.commit()
                    return (jsonify({"status": "Din account blev tilføjet successfuldt!"}), 200)

    except mariadb.Error as e:
        return jsonify({"error": f"Der opstod en fejl: {str(e)}"}), 500


# Used when the service is listed only once. Deletes using only service and user_id.
@user_bp.route("/services/remove", methods=["DELETE"])
@limiter.limit("100/hour")
def remove_service():
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
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                if username:
                    cursor.execute("DELETE FROM user_info WHERE service = %s AND username = %s AND user_id = %s", (service, username, user_id),)

                else:
                    cursor.execute("DELETE FROM user_info WHERE service = %s AND user_id = %s", (service, user_id),)

                if cursor.rowcount == 0:
                    return jsonify({"error": "Service-navnet findes ikke!"}), 404

                conn.commit()
                return (jsonify({"status": "Succes! Dine oplysninger blev slettet!"}), 200,)

    except mariadb.Error as e:
        return jsonify({"error": f"Der opstod en fejl: {str(e)}"}), 500


# Checks if a username is already in the database. Makes sure that each user that is created is unique.
@user_bp.route("/username/availability", methods=["GET"])
@limiter.limit("100/hour")
def check_username():
    data = request.get_json()
    username = data.get("username")
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT username FROM pm_users WHERE username = %s", (username,))
                if cursor.fetchone():
                    return jsonify({"available": False}), 200
                else:
                    return jsonify({"available": True}), 500
    except mariadb.Error as e:
        return jsonify({"error": str(e)}), 500


# Retrieves password when the service is only listed once. Retrieves using only service and user_id.
@user_bp.route("/services/retrieve", methods=["GET"])
@limiter.limit("100/hour")
def password_retriever():
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
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                if username:
                    cursor.execute(
                        "SELECT username, password FROM user_info WHERE service = %s"
                        "AND username = %s AND user_id = %s", (service, username, user_id)
                    )

                else:
                    cursor.execute("SELECT username, password FROM user_info WHERE service = %s AND user_id = %s", (service, user_id))

                retrieved_info = cursor.fetchone()

                if retrieved_info:
                    username, encrypted_password = retrieved_info
                    encryption_key = bytes.fromhex(get_doppler_secrets("ENCRYPTION_KEY"))
                    decrypted_password = pass_decrypt(encryption_key, encrypted_password)

                    return (jsonify({"username": username, "password": decrypted_password}), 200)
                else:
                    return (jsonify({"error": "Service-navnet blev ikke fundet."}), 404)

    except mariadb.Error:
        return jsonify({"error": "database error"}), 500


# Used to delete an account completely along with all its data.
@user_bp.route("/user/accountdelete", methods=["POST"])
@limiter.limit("25/hour")
def delete_account():
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout": "Session timeout!"}), 440
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not check_pass(password, username):
        return jsonify({"error": "unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if tfa_check(username, user_id):
        return jsonify({"tfa_confirm": "tfa_confirm", "username": username}), 200
    else:
        try:
            with pool.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("DELETE FROM user_info WHERE user_id = %s", (user_id,))
                    cursor.execute("DELETE FROM pm_users WHERE user_id = %s", (user_id,))
                    cursor.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
                    conn.commit()
                    session.clear()
                    response = jsonify({"delete_complete": "delete_complete"})
                    response.set_cookie("session_token", "", expires=0)
                    return response
        except mariadb.Error as e:
            return jsonify({"error": str(e)}), 500


@user_bp.route("/account/delete", methods=["POST"])
@limiter.limit("25/hour")
def tfa_account_deletion():
    data = request.get_json()
    username = data.get("username")
    tfa_code = data.get("tfa_code")
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout": "Session timeout!"}), 440

    if validate_tfa(tfa_code, username, user_id):
        try:
            with pool.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("DELETE FROM user_info WHERE user_id = %s", (user_id,))
                    cursor.execute("DELETE FROM pm_users WHERE user_id = %s", (user_id,))
                    cursor.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
                    conn.commit()
                    session.clear()
                    response = jsonify({"delete_complete": "delete_complete"}), 200
                    response.set_cookie("session_token", "", expires=0)
                    return response
        except mariadb.Error as e:
            return jsonify({"error": str(e)}), 500


# Is used to provide a list of the services a specific has stored in the manager already.
@user_bp.route("/services/servicelist", methods=["GET"])
@limiter.limit("1000/hour")
def showlist():
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout": "Session timeout!"}), 440

    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT service, username FROM user_info WHERE user_id = %s ORDER BY service, username", (user_id,)
                )
                retrieved_info = cursor.fetchall()
                services_dict = {}
                for service, username in retrieved_info:
                    if service not in services_dict:
                        services_dict[service] = []
                    services_dict[service].append(username)
                return jsonify({"services": services_dict}), 200

    except mariadb.Error as e:
        return jsonify({"error": str(e)}), 500
