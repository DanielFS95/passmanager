import mariadb
import arrow
from datetime import timedelta, datetime
import base64
from flask import jsonify
from Crypto.Cipher import AES
import bcrypt
from project.common import pool


def pass_encrypt(key, password):
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())
    encrypted_password = nonce + tag + ciphertext
    return base64.b64encode(encrypted_password).decode("utf-8")


# When a user requests to view a password for a specific service, this decrypts the previously encrypted password.
def pass_decrypt(key, encrypted_password_base64):
    encrypted_password = base64.b64decode(encrypted_password_base64)
    nonce = encrypted_password[:16]
    tag = encrypted_password[16:32]
    ciphertext = encrypted_password[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    password = cipher.decrypt_and_verify(ciphertext, tag)
    return password.decode()


# Hashes the password, using bcrypt with the salt option enabled. This is used for account creation.
def hash_pass(password):
    salt = bcrypt.gensalt()
    hash_passw = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hash_passw


# Checks if the password is valid on account login attempt.
def check_pass(password, username):
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT password FROM pm_users WHERE username = %s", (username,))
                result = cursor.fetchone()
                if result:
                    hash_passw = result[0]
                    if isinstance(hash_passw, str):
                        hash_passw = hash_passw.encode("utf-8")
                    if bcrypt.checkpw(password.encode("utf-8"), hash_passw):
                        return True
                    return False
                return False
    except mariadb.Error:
        return False


# Retrives the unique user_id of an account. Needed for specific user-actions.
def get_user_id_with_username(username):
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT user_id FROM pm_users WHERE username = %s", (username,))
                get_ulid = cursor.fetchone()

                if get_ulid is None:
                    return None

                ulid = get_ulid[0]
                return ulid
    except mariadb.Error as e:
        return (e), 500


# Provides a different way to obtain user_id. Useful when functions doesn't have a username to get user_id with.
def get_user_id_with_session_token(session_token):
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT user_id FROM sessions WHERE session_token = %s", (session_token,))
                result = cursor.fetchone()
                if result:
                    return result[0]
                else:
                    return None
    except mariadb.Error as e:
        return jsonify({"error": str(e)}), 500


# Stores the session in the database
def store_session(session_token, user_id, expires_at, username):
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO sessions (session_token, user_id, expires_at, username)"
                    "VALUES(%s, %s, %s, %s)", (session_token, user_id, expires_at, username)
                )
                conn.commit()
                return True
    except mariadb.Error as e:
        return jsonify({"error": str(e)}), 500


# Checks if the session for a user has expired.
def check_session(session_token, user_id):
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT expires_at FROM sessions WHERE session_token = %s"
                    "AND user_id = %s", (session_token, user_id)
                )
                result = cursor.fetchone()
                current_time = arrow.utcnow()
                user_expiration_from_db = result[0]
                user_expiration = arrow.get(user_expiration_from_db)
                if current_time > user_expiration:
                    return False
                else:
                    return True
    except mariadb.Error as e:
        return jsonify({"error": str(e)}), 500


# Updates the expiration date of a already created session.
def update_session(session_token, user_id):
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                current_time = datetime.now() + timedelta(minutes=30)
                cursor.execute(
                    "UPDATE sessions SET expires_at = %s WHERE session_token = %s"
                    "AND user_id = %s", (current_time, session_token, user_id)
                )
                conn.commit()
    except mariadb.Error as e:
        return jsonify({"error": str(e)}), 500
