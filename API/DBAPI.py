import mariadb
import arrow
import datetime
from datetime import timedelta, datetime
from password_validator import PasswordValidator
import os, base64
from flask import Flask, request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from Crypto.Cipher import AES
from dopplersdk import DopplerSDK
import ulid
import bcrypt
import secrets
import pyotp
import logging
import qrcode
from io import StringIO


#Configs and initialization
load_dotenv()
doppler = DopplerSDK()
doppler.set_access_token(os.getenv("DOPPLER_TOKEN"))
app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
app.config["SECRET_KEY"] = os.urandom(24)
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


#Initializes the rate limiter. Checks client IP. Currently not set properly for testing purpose
limiter = Limiter(key_func=get_remote_address,app=app,default_limits=["500 per day", "60 per hour"], strategy="fixed-window")

#Validation of passwords. This is done on both client and server-side.
validatepass = PasswordValidator()
validatepass\
    .min(10)\
    .has().uppercase()\
    .has().lowercase()\
    .has().digits()\
    .no().spaces()



#Retrieving doppler secrets
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
                   
                   
#checks if the user has 2-Factor enabled
def tfa_check(username, user_id):
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT tfa_key FROM pm_users WHERE username = %s AND user_id = %s", (username, user_id))
                result = cursor.fetchone()
                if result is None or not result[0]:
                    return False

                return True
                
    except mariadb.Error as e:
        return e
 
    
#If TFA is enabled, this checks if the user-provided tfa-key is correct.
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
                
    except mariadb.Error as e:
        return e


#When a user inputs a password to be stored. Encrypt it with AES-GCM.
def pass_encrypt(key, password):
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())
    encrypted_password = nonce + tag + ciphertext
    return base64.b64encode(encrypted_password).decode("utf-8")


#When a user requests to view a password for a specific service, this decrypts the previously encrypted password.
def pass_decrypt(key, encrypted_password_base64):
    encrypted_password = base64.b64decode(encrypted_password_base64)
    nonce = encrypted_password[:16]
    tag = encrypted_password[16:32]
    ciphertext = encrypted_password[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    password = cipher.decrypt_and_verify(ciphertext, tag)
    return password.decode()


#Hashes the password, using bcrypt with the salt option enabled. This is used for account creation.
def hash_pass(password):
    salt = bcrypt.gensalt()
    hash_passw = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hash_passw


#Checks if the password is valid on account login attempt.
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
    except mariadb.Error as e:
        return False


#Basic logging. **Not setup at all yet**
#logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')
#logger = logging.getLogger(__name__)


#Retrives the unique user_id of an account. Needed for specific user-actions.
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


#Provides a different way to obtain user_id. Useful when functions doesn't have a username to get user_id with.
def get_user_id_with_session_token(session_token):
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT user_id FROM sessions WHERE session_token = %s",(session_token,))
                result = cursor.fetchone()
                if result:
                    return result[0]
                else:
                    return None
    except mariadb.Error as e:
        return jsonify({"error": str(e)}), 500


#stores the session in the database
def store_session(session_token, user_id, expires_at, username):
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("INSERT INTO sessions (session_token, user_id, expires_at, username) VALUES(%s, %s, %s, %s)",(session_token, user_id, expires_at, username))
                conn.commit()
                return True
    except mariadb.Error as e:
        return jsonify({"error": str(e)}), 500
    
    
#Checks if the session for a user has expired.    
def check_session(session_token, user_id):
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT expires_at FROM sessions WHERE session_token = %s AND user_id = %s", (session_token, user_id))
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
    
    
#updates the expiration date of a already created session.
def update_session(session_token, user_id):
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                current_time = datetime.now() + timedelta(minutes=30)
                cursor.execute("UPDATE sessions SET expires_at = %s WHERE session_token = %s AND user_id = %s", (current_time, session_token, user_id))
                conn.commit()
    except mariadb.Error as e:
        return jsonify({"error": str(e)}), 500



tfa_k = {} #Bruges til at kunne udnytte tfa_k i anden funktion, uden behov for at sende nøglen tilbage igen. (Ingen session oprettet her)
#Generate a qrcode for 2FA
@app.route("/tfa/generate", methods=["POST"])
@limiter.limit("100/hour")
def tfa_generate():
    data = request.get_json()
    username = data.get("username")
    k = pyotp.random_base32()
    two_auth = pyotp.totp.TOTP(k).provisioning_uri(name = username, issuer_name = "Daniel's Password Manager")
    tfa_k[username] = k
    session["username"] = username    
    qr = qrcode.QRCode()
    qr.add_data(two_auth)
    qr.make(fit=True)
    qr_ascii = StringIO()
    qr.print_ascii(out=qr_ascii)
    qr_ascii_string = qr_ascii.getvalue()
        
    return jsonify({"qr_code_succes":qr_ascii_string}), 200


#Used to verify the user provided tfa-key. This function is essentially only used on account creation or when adding 2FA through account settings.
@app.route("/tfa/verify", methods=["POST"])
@limiter.limit("100/hour")
def verify_tfa():
    data = request.get_json()
    username = session.get("username")
    tfa_code = data.get("tfa_code")
    tfa_key = tfa_k[username]
    totp = pyotp.TOTP(tfa_key)
    session.pop("username", None)
    if totp.verify(tfa_code):
        user_id = get_user_id_with_username(username)
        encryption_key = bytes.fromhex(get_doppler_secrets("ENCRYPTION_KEY"))
        key = pass_encrypt(encryption_key, tfa_key)
        try:
            with pool.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("UPDATE pm_users SET tfa_key = %s WHERE user_id = %s AND username = %s",(key, user_id, username),)
                    conn.commit()
        except mariadb.Error as e:
            return jsonify({"error": str(e)})
        return jsonify({"tfa_complete":"succes"}), 200
    else:
        return jsonify({"error":"Cant verify 2FA!"}), 500


#User to "turn off" 2FA for an account
@app.route("/tfa/remove", methods=["DELETE"])      
@limiter.limit("100/hour")
def remove_tfa():
    data = request.get_json()
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout":"Session timeout!"}), 440
    username = data.get("username")
    tfa_code = data.get("tfa_code")
    valid_tfa = validate_tfa(tfa_code, username, user_id)
    if valid_tfa == True:
        try:
            with pool.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("UPDATE pm_users SET tfa_key = NULL WHERE user_id = %s AND username = %s",(user_id, username))
                    conn.commit()
        except mariadb.Error as e:
            return jsonify({"error": str(e)})
        return jsonify({"tfa_removed":"succes"}), 200
    else:
        return jsonify({"error":"There was an issue removing tfa!"}), 500
        
        
#Used for account creation.        
@app.route("/user/register", methods=["PUT"])
@limiter.limit("100/hour")
def user_register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    id = ulid.new().str
    if not all([username, password, id]):
        return jsonify({"error": "Der mangler en eller flere af de påkrævede felter"}), 400
    if not validatepass.validate(password):
        return jsonify({"error":"Password criterias not matched"}), 400
            
    hashed_pass = hash_pass(password)
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("INSERT INTO pm_users (user_id, password, username) VALUES (%s, %s, %s)",(id, hashed_pass, username))
                conn.commit()
                return jsonify({"Account_created": True}), 200
    except mariadb.Error as e:
        return jsonify({"error": str(e)}), 500


#Used for userlogin
@app.route("/user/login", methods=["POST"])
@limiter.limit("100/hour")
@limiter.limit("10/minute")
def user_login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Der mangler en eller flere af de påkrævede felter"}), 400
    if check_pass(password, username) == True:
        user_id = get_user_id_with_username(username)
        session_token = secrets.token_hex(32)
        expires_at = datetime.now() + timedelta(minutes=30)

                
        check_tfa = tfa_check(username, user_id)
            
        if check_tfa:
            return jsonify({"get_tfa_code":"await_user","username":username}), 200
            
        else:
            store_session(session_token, user_id, expires_at, username)
            response = jsonify({"success":"Login succesfuldt!"})
            response.set_cookie("session_token", session_token)
            return response, 200
                
    else:
        return (jsonify({"error": "The username or password provided is incorrect"}),401)


#Checks the user provided tfa-key when user is trying to login.
@app.route("/user/login/2fa", methods=["POST"])
@limiter.limit("100/hour")
@limiter.limit("10/minute")
def tfa_login():
    data = request.get_json()
    tfa_code = data.get("tfa_code")
    username = data.get("username")
    user_id = get_user_id_with_username(username)
    tfa_code_validation = validate_tfa(tfa_code, username, user_id)
    if tfa_code_validation == True:
        session_token = secrets.token_hex(32)
        expires_at = datetime.now() + timedelta(minutes=30)
        store_session(session_token, user_id, expires_at, username)
        response = jsonify({"tfa-success":"Login OK"})
        response.set_cookie("session_token", session_token)
        return response, 200
    else:
        return jsonify({"error":"There was an error!"}), 500


#Used when logging out user. "Pops" the session.
@app.route("/user/logout", methods=["POST"])
@limiter.limit("50/hour")
def user_logout():
    session_token = request.cookies.get("session_token")
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM sessions WHERE session_token = %s", (session_token,))
                conn.commit()
    except mariadb.Error as e:
        return jsonify({"error": "internal error"}), 500

    session.pop("user_id", None)
    return jsonify({"status": "Logged out successfully"}), 200


#Used for adding a new service to the password manager for a specfic account.
@app.route("/user/services", methods=["POST"])
@limiter.limit("100/hour")
def add_service():
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout":"Session timeout!"}), 440
    data = request.get_json()
    if not data:
        return jsonify({"error": "Der er ingen data at hente"}), 400
    update_session(session_token, user_id)
    try:
        if "already_exist" in data:
            userinfo = data["already_exist"]
            service = userinfo.get("service")
            username = userinfo.get("username")
            password = userinfo.get("password")
        else:
            service = data.get("service")
            username = data.get("username")
            password = data.get("password")
            
        id = ulid.new().str

        if not all([service, username, password, id]):
            return (jsonify({"error": "Der mangler en eller flere af de påkrævede felter"}), 400)

        encryption_key = bytes.fromhex(get_doppler_secrets("ENCRYPTION_KEY"))
        encrypt_pass = pass_encrypt(encryption_key, password)
            
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                if "already_exist" in data:
                    cursor.execute("UPDATE user_info SET password = %s WHERE username = %s AND service = %s AND user_id = %s", (encrypt_pass, username, service, user_id))
                    conn.commit()
                    return (jsonify({"pass_overwritten":"completed"})), 200
                else:    
                    cursor.execute("INSERT INTO user_info (ulid, user_id, service, password, username) VALUES (%s, %s, %s, %s, %s)",(id, user_id, service, encrypt_pass, username))
                    conn.commit()
                    return (jsonify({"status": "Din account blev tilføjet successfuldt!"}),200)
                    
    except mariadb.Error as e:
        return jsonify({"error": f"Der opstod en fejl: {str(e)}"}), 500            
                    
                    
#If the same service is listed more than once, this function is used to remove the specific account. Deletes based on service, user_id AND password.                    
@app.route("/user/services/removespecific", methods=["DELETE"])
@limiter.limit("100/hour")                 
def remove_specific_service():
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout":"Session timeout!"}), 440
    data = request.get_json()
    if not data:
        return jsonify({"error": "Der er ingen data at hente"}), 400
    update_session(session_token, user_id)
        
    service = data.get("service")
    username = data.get("account")
    if not all([service, username]):
        return (jsonify({"error": "Der mangler en eller flere af de påkrævede felter"}), 400)
    try:
        with pool.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("DELETE FROM user_info WHERE service = %s AND username = %s AND user_id = %s",(service, username, user_id),)
                    if cursor.rowcount == 0:
                        return (jsonify({"error": "Service-navnet eller brugernavnet findes ikke!"}),404,)
                    conn.commit()
                    return jsonify({"status": "Oplysninger slettet"}), 200
    except mariadb.Error as e:
        return jsonify({"error":str(e)}), 500
    
    
#Used when the service is listed only once. Deletes using only service and user_id. 
@app.route("/user/services/remove", methods=["DELETE"])
@limiter.limit("100/hour")    
def remove_service():
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout":"Session timeout!"}), 440
    data = request.get_json()
    if not data:
        return jsonify({"error": "Der er ingen data at hente"}), 400
    update_session(session_token, user_id)    
    
    service = data.get("service")
    if not service:
        return (jsonify({"error": "Der mangler en eller flere af de påkrævede felter"}),400)
    try:
        with pool.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("DELETE FROM user_info WHERE service = %s AND user_id = %s",(service, user_id),)
                    if cursor.rowcount == 0:
                        return jsonify({"error": "Service-navnet findes ikke!"}), 404
                    conn.commit()
                    return (jsonify({"status": "Succes! Dine oplysninger blev slettet!"}),200,)

    except mariadb.Error as e:
        return jsonify({"error": f"Der opstod en fejl: {str(e)}"}), 500


#Checks if a username is already in the database. Makes sure that each user that is created is unique.
@app.route("/usernames/availability", methods=["GET"])
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


#Retrieves a password where the service is listed more than once. Retrieves based on service, user_id and username.
@app.route("/user/services/retrievespecific", methods=["GET"])
@limiter.limit("100/hour")
def password_retriever():
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout":"Session timeout!"}), 440
    update_session(session_token, user_id)
    
    data = request.get_json()
    service = data.get("service")
    username = data.get("account")
    
    if not service:
        return (jsonify({"error": "Der mangler en eller flere af de påkrævede felter"}),400,)
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT username, password FROM user_info WHERE service = %s AND username = %s AND user_id = %s",(service, username ,user_id))
                retrieved_info = cursor.fetchone()

                if retrieved_info:
                    username, encrypted_password = retrieved_info
                    encryption_key = bytes.fromhex(get_doppler_secrets("ENCRYPTION_KEY"))
                    decrypted_password = pass_decrypt(encryption_key, encrypted_password)

                    return (jsonify({"username": username, "password": decrypted_password}), 200)
                        
                else:
                    return (jsonify({"error": "Service-navnet blev ikke fundet."}), 404)

    except mariadb.Error as e:
        return jsonify({"error": str(e)}), 500


#retrieves password when the service is only listed once. Retrieves using only service and user_id.
@app.route("/user/services/retrieve", methods=["GET"])
@limiter.limit("100/hour")
def password_retriever2():
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout":"Session timeout!"}), 440
    update_session(session_token, user_id)
    
    data = request.get_json()
    service = data.get("service")
    if not service:
        return (jsonify({"error": "Der mangler en eller flere af de påkrævede felter"}),400)

    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT username, password FROM user_info WHERE service = %s AND user_id = %s",(service, user_id),)
                retrieved_info = cursor.fetchone()

                if retrieved_info:
                    username, encrypted_password = retrieved_info
                    encryption_key = bytes.fromhex(get_doppler_secrets("ENCRYPTION_KEY"))
                    decrypted_password = pass_decrypt(encryption_key, encrypted_password)

                    return (jsonify({"username": username, "password": decrypted_password}),200)
                else:
                    return (jsonify({"error": "Service-navnet blev ikke fundet."}),404)

    except mariadb.Error as e:
        return jsonify({"error": str(e)}), 500


#used to delete an account completely along with all its data.
@app.route("/user/accountdelete", methods=["POST"])
@limiter.limit("25/hour")
def delete_account():
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout":"Session timeout!"}), 440
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not check_pass(password, username):
        return jsonify({"error":"unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token) 
    if tfa_check(username, user_id):
        return jsonify({"tfa_confirm":"tfa_confirm", "username":username}), 200
    else:
        try:
            with pool.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("DELETE FROM user_info WHERE user_id = %s",(user_id,))
                    cursor.execute("DELETE FROM pm_users WHERE user_id = %s",(user_id,))
                    cursor.execute("DELETE FROM sessions WHERE user_id = %s",(user_id,))
                    conn.commit()
                    session.clear()
                    response = jsonify({"delete_complete":"delete_complete"})
                    response.set_cookie("session_token", "", expires=0)
                    return response
        except mariadb.Error as e:
            return jsonify({"error": str(e)}), 500
        
        
#Used when the user chooses to remove the 2FA through account settings.       
@app.route("/user/accountdelete/tfa", methods=["POST"])
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
        return jsonify({"timeout":"Session timeout!"}), 440
    
    if validate_tfa(tfa_code, username, user_id):
        try:
            with pool.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("DELETE FROM user_info WHERE user_id = %s",(user_id,))
                    cursor.execute("DELETE FROM pm_users WHERE user_id = %s",(user_id,))
                    cursor.execute("DELETE FROM sessions WHERE user_id = %s",(user_id,))
                    conn.commit()
                    session.clear()
                    response = jsonify({"delete_complete":"delete_complete"}), 200
                    response.set_cookie("session_token", "", expires=0)
                    return response
        except mariadb.Error as e:
            return jsonify({"error": str(e)}), 500


#Is used to provide a list of the services a specific has stored in the manager already.
@app.route("/user/services/servicelist", methods=["GET"])
@limiter.limit("1000/hour")
def showlist():
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_user_id_with_session_token(session_token)
    if not check_session(session_token, user_id):
        return jsonify({"timeout":"Session timeout!"}), 440
    
    try:
        with pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT service, username FROM user_info WHERE user_id = %s ORDER BY service, username",(user_id,))
                retrieved_info = cursor.fetchall()
                services_dict = {}
                for service, username in retrieved_info:
                    if service not in services_dict:
                        services_dict[service] = []
                    services_dict[service].append(username)
                return jsonify({"services": services_dict}), 200

    except mariadb.Error as e:
        return jsonify({"error": str(e)}), 500



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
