from flask import Blueprint
import mariadb
from datetime import timedelta, datetime
from flask import request, jsonify, session
import secrets
import pyotp
import qrcode
import logging
import sys
from io import StringIO
from project.common import get_connection_pool, get_doppler_secrets, limiter
from project.auth_tools import get_user_id_with_username, get_user_id_with_session_token, check_session, store_session, pass_decrypt, pass_encrypt

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)])

tfa_bp = Blueprint('tfa', __name__)

pool = get_connection_pool()

store_secret_key = {}      # Bruges til at kunne udnytte store_secret_key i anden funktion, uden behov for at sende nøglen tilbage igen. (Ingen session oprettet her)


# Generate a qrcode for 2FA
@tfa_bp.route("/generate", methods=["POST"])
@limiter.limit("100/hour")
def tfa_generate():
    data = request.get_json()
    username = data.get("username")
    secret_key = pyotp.random_base32()
    two_auth = pyotp.totp.TOTP(secret_key).provisioning_uri(name=username, issuer_name="Daniel's Password Manager")
    store_secret_key[username] = secret_key
    session["username"] = username
    qr = qrcode.QRCode()
    qr.add_data(two_auth)
    qr.make(fit=True)
    qr_ascii = StringIO()
    qr.print_ascii(out=qr_ascii)
    qr_ascii_string = qr_ascii.getvalue()

    return jsonify({"qr_code_succes": qr_ascii_string}), 200


@tfa_bp.route("/verify", methods=["POST"])
@limiter.limit("100/hour")
def verify_tfa():
    data = request.get_json()
    username = session.get("username")
    tfa_code = data.get("tfa_code")
    tfa_key = store_secret_key.get(username)
    totp = pyotp.TOTP(tfa_key)
    session.pop("username", None)
    if totp.verify(tfa_code):
        user_id = get_user_id_with_username(username)
        encryption_key = bytes.fromhex(get_doppler_secrets("ENCRYPTION_KEY"))
        key = pass_encrypt(encryption_key, tfa_key)
        try:
            with pool.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE pm_users SET tfa_key = %s WHERE user_id = %s AND username = %s", (key, user_id, username),
                    )
                    conn.commit()
        except mariadb.Error as e:
            return jsonify({"error": str(e)})
        store_secret_key.pop(username, None)
        return jsonify({"tfa_complete": "succes"}), 200
    else:
        return jsonify({"error": "Cant verify 2FA!"}), 500


@tfa_bp.route("/remove", methods=["DELETE"])
@limiter.limit("100/hour")
def remove_tfa():
    data = request.get_json()
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout": "Session timeout!"}), 440
    username = data.get("username")
    print(username)
    logging.debug(username)
    tfa_code = data.get("tfa_code")
    logging.debug(tfa_code)
    logging.debug(user_id)
    valid_tfa = validate_tfa(tfa_code, username, user_id)
    if valid_tfa is True:
        try:
            with pool.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE pm_users SET tfa_key = NULL WHERE user_id = %s AND username = %s", (user_id, username)
                        )
                    conn.commit()
        except mariadb.Error as e:
            return jsonify({"error": str(e)})
        return jsonify({"tfa_removed": "succes"}), 200
    else:
        return jsonify({"error": "There was an issue removing tfa!"}), 500


# Checks the user provided tfa-key when user is trying to login.
@tfa_bp.route("/check-tfa", methods=["POST"])
@limiter.limit("100/hour")
@limiter.limit("10/minute")
def tfa_login():
    data = request.get_json()
    tfa_code = data.get("tfa_code")
    username = data.get("username")
    user_id = get_user_id_with_username(username)
    tfa_code_validation = validate_tfa(tfa_code, username, user_id)
    if tfa_code_validation is True:
        session_token = secrets.token_hex(32)
        expires_at = datetime.now() + timedelta(minutes=30)
        store_session(session_token, user_id, expires_at, username)
        response = jsonify({"tfa-success": "Login OK"})
        response.set_cookie("session_token", session_token)
        return response, 200
    else:
        return jsonify({"error": "There was an error!"}), 500


# Checks if the user has 2-Factor enabled
def tfa_check(username, user_id):
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT tfa_key FROM pm_users WHERE username = %s AND user_id = %s", (username, user_id))
                result = cursor.fetchone()
                if result is None or not result[0]:
                    return False

                return True

    except mariadb.Error:
        return False, 500


# If TFA is enabled, this checks if the user-provided tfa-key is correct.
def validate_tfa(tfa_code, username, user_id):
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT tfa_key FROM pm_users WHERE username = %s AND user_id = %s", (username, user_id))
                result = cursor.fetchone()
                encrypted_tfa_key = result[0]
                encryption_key = bytes.fromhex(get_doppler_secrets("ENCRYPTION_KEY"))
                decrypted_key = pass_decrypt(encryption_key, encrypted_tfa_key)
                totp = pyotp.TOTP(decrypted_key)
                if totp.verify(tfa_code):
                    return True
                else:
                    return False

    except mariadb.Error:
        return False, 500
