from .common import console, clear_screen, s, logged_in_username


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
