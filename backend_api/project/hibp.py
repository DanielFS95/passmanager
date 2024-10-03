from auth_tools import pass_decrypt
import pyhibp
from pyhibp import pwnedpasswords as pw
import hashlib


def hibp_password_leak(decrypted_pass):
    pyhibp.set_user_agent(ua="Daniels Password Manager")
    hashed_pass = hashlib.sha1(decrypted_pass.encode()).hexdigest()
    response = pw.is_password_breached(password=hashed_pass)
    return response

    
    
    
    