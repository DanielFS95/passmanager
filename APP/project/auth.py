import requests
import pwinput
from password_validator import PasswordValidator
from .common import console, clear_screen

s = requests.Session()


validatepass = PasswordValidator()
validatepass\
    .min(10)\
    .has().uppercase()\
    .has().lowercase()\
    .has().digits()\
    .no().spaces()

logged_in_username = None


def login(username, password):
    global logged_in_username
    login_info = {"username": username, "password": password}
    r = s.post("https://api.dfsprojekt.dk/user/login", json=login_info, headers={"Content-Type": "application/json"})

    if r.status_code == 200 and r.json().get("success"):
        print("Du er nu logget på!")
        logged_in_username = username
        return True
    elif r.status_code == 200 and r.json().get("get_tfa_code"):
        username = r.json().get("username")
        tfa_code = input("Indtast din 2FA Kode: ")
        jsondata = {"tfa_code": tfa_code, "username": username}
        r = s.post("https://api.dfsprojekt.dk/user/login/2fa", json=jsondata, headers={"Content-Type": "application/json"})
        if r.status_code == 200 and r.json().get("tfa-success"):
            print("Succes! du er nu logget på!")
            logged_in_username = username
            return True

    print("Dit login fejlede!")
    return False


def create_user():
    while True:
        username = input("Username: ")
        if username == "b":
            clear_screen()
            return True

        # Check if the username is available
        if not check_username(username):
            console.print("[bold bright_red]Brugernavnet er allerede taget. Prøv et andet![/bold bright_red]")
            continue

        while True:
            print("\n")
            console.print("[italic underline](Dit password skal være mindst 10 karakterer langt og skal indeholde både store og små bogstaver samt mindst ét tal.)[/italic underline]")
            print("\n")
            password = pwinput.pwinput("Password: ")
            if password == "b":
                clear_screen()
                return True
            elif not validatepass.validate(password):
                console.print("[bold bright_red]Dit password lever ikke op til kravene! Vælg et nyt![/bold bright_red]")
                continue
            password_confirm = pwinput.pwinput("Bekræft dit password: ")
            if password_confirm == "b":
                clear_screen()
                return True
            if password != password_confirm:
                console.print("[bold bright_red]Dine passwords matcher ikke. Prøv igen.[/bold bright_red]")
                continue
            break

        # Send registration request
        userinfo = {"username": username, "password": password}
        headers = {"Content-Type": "application/json"}
        try:
            r = s.put("https://api.dfsprojekt.dk/user/register", json=userinfo, headers=headers)
            r.raise_for_status()  # Ensure the request was successful
        except requests.RequestException as e:
            console.print(f"[bold bright_red]Der opstod en fejl ved oprettelsen af din konto: {e}[/bold bright_red]")
            return False

        # Check if the account was created successfully
        if r.json().get("Account_created", False):
            clear_screen()
            console.print(f"[bold bright_green]Din account med brugernavnet[/bold bright_green] [underline]{username}[/underline][bold bright_green] blev oprettet succesfuldt![/bold bright_green]")
            print("\n")
            user_tfa_choice = input("Ønsker du at tilføje 2FA til din account? (j/n): ")
            if user_tfa_choice.lower() == "j":
                if two_factor_qrcode(username):
                    console.print("[bold bright_red]Der opstod et problem med 2FA opsætning. Prøv igen senere.[/bold bright_red]")
                    return False
                else:
                    clear_screen()
                    print(f"2FA blev tilføjet for {username}!")
            else:
                clear_screen()
                console.print("[italic]2FA blev fravalgt. Du kan altid tilføje det under dine account indstillinger.[/italic]")
                print("\n")
            return True
        else:
            console.print("[bold bright_red]Der opstod et problem under konto oprettelsen.[/bold bright_red]")
            return False


def delete_user():
    global logged_in_username
    while True:
        last_choice = input("Er du helt sikker på at du vil slette din account og alle dets data? Du kan ikke fortryde denne handling efter den er udført!(j/n): ")
        if last_choice == "n":
            clear_screen()
            return
        elif last_choice == "j":
            clear_screen()
            break
        else:
            clear_screen()
            print("Ugyldigt input! Bekræft venligst at du ønsker at slette din account")
            continue
    console.print("[underline]For at kunne slette din account skal du bekræfte med Password og 2FA (Såfremt 2FA er aktivt)[/underline]")
    password = pwinput.pwinput("Indtast dit password: ")
    username = logged_in_username
    headers = {"Content-Type": "application/json"}
    jsondata = {"username": username, "password": password}
    r = s.post("https://api.dfsprojekt.dk/user/accountdelete", json=jsondata, headers=headers)
    if r.status_code == 200 and r.json().get("tfa_confirm"):
        username = r.json().get("username")
        tfa_code = input("Indtast din 2FA Kode: ")
        jsondata = {"tfa_code": tfa_code, "username": username}
        r = s.post("https://api.dfsprojekt.dk/user/accountdelete/tfa", json=jsondata, headers=headers)
        if r.status_code == 200 and r.json().get("delete_complete"):
            clear_screen()
            console.print("Din account og dets data blev slettet!")
        else:
            console.print("Der opstod et problem, og din account blev ikke slettet!")
    elif r.status_code == 200 and r.json().get("delete_complete"):
        clear_screen()
        console.print("Din account og dets data blev slettet!")


def check_if_session():
    if not s.cookies:
        console.print("[bold bright_red]Du skal være logget ind først![/bold bright_red]")
        return False
    return True


def logout():
    if check_if_session is False:
        console.print("[bold bright_red]Du skal være logget ind først![/bold bright_red]")
        return False
    try:
        r = s.post("https://api.dfsprojekt.dk/user/logout", headers={"Content-Type": "application/json"})
        if r.status_code == 200:
            print("Du blev logget ud!")
            s.cookies.clear()
    except requests.RequestException as e:
        print(f"Der opstod en fejl: {e}")


def check_username(username):
    headers = {"Content-Type": "application/json"}
    jsondata = {"username": username}
    t = s.get("https://api.dfsprojekt.dk/usernames/availability", json=jsondata, headers=headers)
    return t.json().get("available", False)


def remove_tfa():
    global logged_in_username
    console.print("[underline] Skriv \"b\" for at fortryde og vende tilbage til menuen [/underline]\n")
    tfa_code = input("Indtast din 2FA Kode: ")
    if tfa_code == "b":
        clear_screen()
        return
    username = logged_in_username
    headers = {"Content-Type": "application/json"}
    jsondata = {"username": username, "tfa_code": tfa_code}
    r = s.delete("https://api.dfsprojekt.dk/tfa/remove", json=jsondata, headers=headers)
    if r.status_code == 200 and r.json().get("tfa_removed"):
        clear_screen()
        console.print("[bold bright_green]2FA blev fjernet succesfuldt![/bold bright_green]")
    else:
        clear_screen()
        console.print("[bold bright_red]Der opstod et problem, og 2FA blev ikke fjernet fra din account[/bold bright_red]")


def two_factor_qrcode(username=None):
    global logged_in_username
    username = username or logged_in_username
    jsondata = {"username": username}
    headers = {"Content-Type": "application/json"}
    r = s.post("https://api.dfsprojekt.dk/tfa/generate", json=jsondata, headers=headers)
    data = r.json().get("qr_code_succes")
    print(data)
    if r.status_code == 200 and r.json().get("qr_code_succes"):
        while True:
            tfa_code = input("Indtast en 2FA-Kode for at forsætte: ")
            headers = {"Content-Type": "application/json"}
            jsondata = {"tfa_code": tfa_code}
            r = s.post("https://api.dfsprojekt.dk/tfa/verify", json=jsondata, headers=headers)
            if r.status_code == 200 and r.json().get("tfa_complete"):
                return False
            elif r.status_code == 200 and r.json.get("error"):
                console.print("Der var et problem!")
                return True
            elif tfa_code == "b":
                break
        return True
