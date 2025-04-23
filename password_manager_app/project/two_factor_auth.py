from .common import console, clear_screen, s
from .art import dpm_logo

def remove_tfa(username):
    console.print(dpm_logo)
    console.print("[italic]Enter \"b\" to return to the menu[/italic\n]")
    tfa_code = input("Enter your 2FA-Code: ")
    if tfa_code == "b":
        clear_screen()
        return
    headers = {"Content-Type": "application/json"}
    jsondata = {"username": username, "tfa_code": tfa_code}
    r = s.delete("https://api.dfsprojekt.dk/tfa/remove", json=jsondata, headers=headers)
    if r.status_code == 200 and r.json().get("tfa_removed"):
        clear_screen()
        console.print("[bold bright_green]2FA has been removed sucessfully![/bold bright_green]")
    else:
        clear_screen()
        console.print("[bold bright_red]There was an issue. 2FA was not removed from your account. Please try again later or contact the developer for support.[/bold bright_red]")


def two_factor_qrcode(username):
    jsondata = {"username": username}
    headers = {"Content-Type": "application/json"}
    r = s.post("https://api.dfsprojekt.dk/tfa/generate", json=jsondata, headers=headers)
    data = r.json().get("qr_code_succes")
    print(data)
    if r.status_code == 200 and r.json().get("qr_code_succes"):
        while True:
            tfa_code = input("Enter your 2FA-Code to continue: ")
            headers = {"Content-Type": "application/json"}
            jsondata = {"tfa_code": tfa_code}
            if tfa_code == "b":
                clear_screen()
                break
            else:
                r = s.post("https://api.dfsprojekt.dk/tfa/verify", json=jsondata, headers=headers)
                if r.status_code == 200 and r.json().get("tfa_complete"):
                    clear_screen()
                    
                    return True
                elif r.status_code == 500 and r.json().get("error"):
                    console.print("There was an issue with the 2FA code. Please try again.")
                    return False
                else:
                    console.print("[bold bright_red]There was an issue, 2FA was not added to your account![/bold bright_red]")
        return True
    else:
        console.print("[bold bright_red]There was an issue generating the QR-Code. Please try again later![/bold bright_red]")
        return True
