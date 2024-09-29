from flask import Blueprint, request, jsonify, session
import mariadb
from datetime import timedelta, datetime
import ulid
import secrets
from common import limiter, validatepass, pool
from auth_tools import hash_pass, store_session, check_pass, get_user_id_with_username
from two_factor_auth import tfa_check

auth_bp = Blueprint('account', __name__)


@auth_bp.route("/register", methods=["PUT"])
@limiter.limit("100/hour")
def user_register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    id = ulid.new().str
    if not all([username, password, id]):
        return jsonify({"error": "Der mangler en eller flere af de påkrævede felter"}), 400
    if not validatepass.validate(password):
        return jsonify({"error": "Password criterias not matched"}), 400

    hashed_pass = hash_pass(password)
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO pm_users (user_id, password, username)"
                    "VALUES (%s, %s, %s)", (id, hashed_pass, username)
                )
                conn.commit()
                return jsonify({"Account_created": True}), 200
    except mariadb.Error as e:
        return jsonify({"error": str(e)}), 500


# Used for userlogin
@auth_bp.route("/login", methods=["POST"])
@limiter.limit("100/hour")
@limiter.limit("10/minute")
def user_login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Der mangler en eller flere af de påkrævede felter"}), 400
    if check_pass(password, username) is True:
        user_id = get_user_id_with_username(username)
        session_token = secrets.token_hex(32)
        expires_at = datetime.now() + timedelta(minutes=30)

        check_tfa = tfa_check(username, user_id)

        if check_tfa:
            return jsonify({"get_tfa_code": "await_user", "username": username}), 200

        else:
            store_session(session_token, user_id, expires_at, username)
            response = jsonify({"success": "Login succesfuldt!"})
            response.set_cookie("session_token", session_token)
            response.set_cookie("username", username)
            return response, 200

    else:
        return (jsonify({"error": "The username or password provided is incorrect"}), 401)


# Used when logging out user. "Pops" the session.
@auth_bp.route("/logout", methods=["POST"])
@limiter.limit("50/hour")
def user_logout():
    session_token = request.cookies.get("session_token")
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM sessions WHERE session_token = %s", (session_token,))
                conn.commit()
    except mariadb.Error:
        return jsonify({"error": "internal error"}), 500

    session.pop("user_id", None)
    return jsonify({"status": "Logged out successfully"}), 200
