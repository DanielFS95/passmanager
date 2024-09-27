import requests
import msvcrt
from tabulate import tabulate
import pwinput
from password_validator import PasswordValidator
import os
from rich.console import Console

s = requests.Session()
console = Console()

validatepass = PasswordValidator()
validatepass\
    .min(10)\
    .has().uppercase()\
    .has().lowercase()\
    .has().digits()\
    .no().spaces()

logged_in_username = None


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


def remove_tfa():
    global logged_in_username
    tfa_code = input("Indtast din 2FA Kode: ")
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


def check_username(username):
    headers = {"Content-Type": "application/json"}
    jsondata = {"username": username}
    t = s.get("https://api.dfsprojekt.dk/usernames/availability", json=jsondata, headers=headers)
    return t.json().get("available", False)


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


def login(username, password):
    global logged_in_username
    login_info = {"username": username, "password": password}
    r = s.post("https://api.dfsprojekt.dk/user/login",json=login_info, headers={"Content-Type": "application/json"})

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


def logout():
    if not s.cookies:
        console.print("[bold bright_red]Du skal være logget ind først![/bold bright_red]")
        return False
    try:
        r = s.post("https://api.dfsprojekt.dk/user/logout", headers={"Content-Type": "application/json"})
        if r.status_code == 200:
            print("Du blev logget ud!")
            s.cookies.clear()
    except requests.RequestException as e:
        print(f"Der opstod en fejl: {e}")


def add_service():
    if not s.cookies.get("session_token"):
        console.print("[bold bright_red]Du skal være logget ind først![/bold bright_red]")
        return False

    console.print("[bold cyan]Tilføj en service til Password Manageren[/bold cyan]")
    print("\n")
    console.print('[italic underline]Skriv "b" for at fortryde og vende tilbage til menuen[/italic underline]\n')

    service = input("Hvilken service ønsker du at tilføje et password for: ")
    if service == "b":
        return "break"
    username = input(f"Indtast username/email som du bruger til {service}: ")
    if username == "b":
        return "break"
    password = input(f"Indtast nu det password du bruger til {username}: ")
    if password == "b":
        return "break"

    userinfo = None
    account_found = False
    service_found = False

    if password and username and service:
        try:
            r = s.get("https://api.dfsprojekt.dk/user/services/servicelist")
            r.raise_for_status()
        except requests.RequestException as e:
            print({e})
            return False

        servicelist = r.json()
        if "services" in servicelist:
            for saved_service, accounts in servicelist["services"].items():
                if service.lower() == saved_service.lower():
                    service_found = True
                    for account in accounts:
                        if username.lower() == account.lower():
                            account_found = True
                            console.print(f"\n[yellow]Der er allerede gemt et password for [white underline]{username}[/white underline] ved servicen [white underline]{service}[/white underline][/yellow]\n")
                            choice = input("Ønsker du at overskrive det tidligere gemte password?(j/n): ")
                            if choice == "j":
                                userinfo = {"already_exist": {"service": service, "username": username, "password": password}}
                            else:
                                console.print("[red]Dit password blev ikke ændret![/red]")
                                return False
                    if not account_found:
                        userinfo = {"service": service, "username": username, "password": password}
                        break

            if not service_found:
                userinfo = {"service": service, "username": username, "password": password}

    headers = {"Content-Type": "application/json"}
    r = s.post("https://api.dfsprojekt.dk/user/services", json=userinfo, headers=headers)
    if r.json().get("status", False):
        print("\n")
        console.print(f"[bold bright_green]Success! Dit password til [/bold bright_green][underline]{service}[/underline][bold bright_green] for [/bold bright_green][underline]{username}[/underline] [bold bright_green]blev tilføjet til Password Manageren![/bold bright_green]")
        return True
    elif r.json().get("pass_overwritten", False):
        print("\n")
        console.print(f"[bold bright_green]Success! Dit password til accounten [white underline]{username}[/white underline] for servicen [white underline]{service}[/white underline] blev opdateret![/bold bright_green]")
    elif r.json().get("timeout"):
        print("\n")
        console.print("[underline yellow italic] Din session er udløbet! Log ind igen![/underline yellow italic]")

        console.print("[bold bright_red]Der skete en fejl![/bold bright_red]")
        return False


def retrieve_password():
    if not s.cookies:
        console.print("[bold bright_red]Du skal være logget ind først![/bold bright_red]")
        return False

    try:
        r = s.get("https://api.dfsprojekt.dk/user/services/servicelist")
        r.raise_for_status()
    except requests.RequestException as e:
        print({e})
        return False

    servicelist = r.json()
    if "services" in servicelist:
        table_data = []
        for service in servicelist["services"]:
            table_data.append([service])
        if len(table_data) == 0:
            return False
        table = tabulate(table_data, headers=["Service"], tablefmt="grid")
        print("\n")
        print(table)

    service_choice = input("\nHvilken service ønsker du at se password for?: ")

    if service_choice not in servicelist["services"]:
        console.print(f"\n\n[underline]{service_choice}[/underline] [bold bright_red]er ikke en gemt service. Vælg venligst en gyldig service.[/bold bright_red]\n\n")
        return False

    accounts = servicelist["services"][service_choice]
    if len(accounts) > 1:
        console.print(f"\n[italic]Der blev fundet {len(accounts)} accounts fra servicen[/italic] [underline]{service_choice}[/underline]:")
        for account in accounts:
            console.print(f"[bold]{account}[/bold]")
        chosen_account = input("\nHvilken account ønsker du at se password for?: ")
        userinfo = {"service": service_choice, "account": chosen_account}
        try:
            headers = {"Content-Type": "application/json"}
            r = s.get("https://api.dfsprojekt.dk/user/services/retrievespecific", json=userinfo, headers=headers)
        except requests.RequestException as e:
            print({e})
            return False
    else:
        userinfo = {"service": service_choice}

        try:
            headers = {"Content-Type": "application/json"}
            r = s.get("https://api.dfsprojekt.dk/user/services/retrieve", json=userinfo, headers=headers)
        except requests.RequestException as e:
            print({e})
            return False

    try:
        jsondata = r.json()
        if "username" and "password" in jsondata:
            username = jsondata["username"]
            password = jsondata["password"]

            console.print(f"\n\n[bold]Username/Email:[/bold] [underline]{username}[/underline]")
            console.print(f"[bold]Password:[/bold] [underline]{password}[/underline]")
            print("\n\n")
            return True
    except s.exceptions.JSONDecodeError as e:
        print("Der opstod en JSONDecode fejl:", e)
    return False


def remove_pass():
    if not s.cookies:
        console.print("[bold bright_red]Du skal være logget ind først![/bold bright_red]")
        return False

    try:
        r = s.get("https://api.dfsprojekt.dk/user/services/servicelist")
        r.raise_for_status()
    except requests.RequestException as e:
        print({e})
        return False

    servicelist = r.json()
    if "services" in servicelist:
        table_data = []
        for service in servicelist["services"]:
            table_data.append([service])
        if len(table_data) == 0:
            return False
        else:
            table = tabulate(table_data, headers=["Service"], tablefmt="grid")
            print("\n")
            print(table)

    service_choice = input("\nHvilken account/password ønsker du at fjerne?: ")

    if service_choice not in servicelist["services"]:
        print("\n")
        console.print(f"\n\n[underline]{service_choice}[/underline] [bold bright_red]er ikke en gemt service. Vælg venligst en gyldig service.[/bold bright_red]\n\n")
        return False

    accounts = servicelist["services"][service_choice]
    if len(accounts) > 1:
        print("\n")
        console.print(f"[italic]Der blev fundet {len(accounts)} accounts fra servicen[/italic] [underline]{service_choice}[/underline]:")
        for account in accounts:
            console.print(f"[bold]{account}[/bold]")
        chosen_account = input(f"Hvilken account ønsker du at fjerne fra {service_choice}?: ")

        userinfo = {"service": service_choice, "account": chosen_account}
        try:
            r2 = s.delete("https://api.dfsprojekt.dk/user/services/removespecific", json=userinfo, headers={"Content-Type": "application/json"},)
            r2.raise_for_status()
            if r2.json().get("status", False):
                print("\n")
                console.print("[bold bright_green]Dine oplysninger blev slettet succesfuldt![/bold bright_green]")
                return True

        except requests.RequestException as e:
            print(f"Der opstod en fejl: {e}")
            return False

    else:
        userinfo = {"service": service_choice}
        try:
            r2 = s.delete("https://api.dfsprojekt.dk/user/services/remove", json=userinfo, headers={"Content-Type": "application/json"},)
            r2.raise_for_status()
            if r2.json().get("status", False):
                print("\n")
                console.print("[bold bright_green]Dine oplysninger blev slettet succesfuldt![/bold bright_green]")
                return True

        except requests.RequestException as e:
            print(f"Der opstod en fejl: {e}")
            return False


def list_services():
    if not s.cookies:
        console.print("[bold bright_red]Du skal være logget ind først![/bold bright_red]")
        return False

    try:
        r = s.get("https://api.dfsprojekt.dk/user/services/servicelist")
        r.raise_for_status()
    except requests.RequestException as e:
        print({e})
        return False

    servicelist = r.json()
    if "services" in servicelist:
        table_data = []
        for service, accounts in servicelist["services"].items():
            for account in accounts:
                table_data.append([service, account])
        table = tabulate(table_data, headers=["Service", "Username/Account"], tablefmt="grid")
        console.print("\n[bold]Du har passwords for følgende services:[/bold]")
        print(table)


def clear_screen():
    os.system("cls")


if __name__ == "__main__":
    logged_in = False
    while True:
        if not s.cookies:
            console.print("[bold yellow]Velkommen til Daniel's Password Manager![/bold yellow]")
            console.print("[italic]\nLog ind eller opret en konto for at bruge Password Manageren[/italic]")
            console.print("\n[underline green]1. Log ind[/underline green]")
            console.print("[underline orange3]2. Opret account[/underline orange3]")
            console.print("[underline red]3. Exit applikationen[/underline red]")
            choice_start = input("\n\nHvad ønsker du at gøre?: ")
            if choice_start == "1":
                clear_screen()
                while True:
                    console.print('[bold]Indtast venligst dine login oplysninger til Daniel\'s Password Manager (Skriv "b" for at vende tilbage til menuen)[/bold]\n')
                    username = input("Username: ")
                    if username == "b":
                        clear_screen()
                        break
                    password = pwinput.pwinput("Password: ")
                    if password == "b":
                        clear_screen()
                        break
                    logged_in = login(username, password)
                    clear_screen()
                    if logged_in:
                        console.print(f"[bold bright_green]Du er nu logget ind som bruger:[/bold bright_green] [bold underline bright_green]{username}[/bold underline bright_green]")
                        break
                    else:
                        console.print("[bold bright_red]Login mislykkedes![/bold bright_red]")

            elif choice_start == "2":
                clear_screen()
                console.print("[bold cyan]Opret en konto for at bruge Daniels Password Manager.[/bold cyan]")
                console.print("[italic]Skriv \"b\" i enten username eller password feltet for at afbryde oprettelsen[/italic]")
                print("\n")
                account_created = create_user()
                if not account_created:
                    console.print("Der opstod et problem, og din account blev ikke oprettet!")

            elif choice_start == "3":
                break

            else:
                clear_screen()
                console.print("[bold bright_red]Ikke en valgmulighed, prøv igen.[/bold bright_red]")

        else:
            if not s.cookies:
                print("Du skal være logget ind for at kunne bruge password manageren!")
                break
            list_services()
            print("\n")
            console.print("[underline yellow]Du har nu følgende valgmuligheder:[/underline yellow]")
            console.print("\n")
            console.print("[bright_green]1. Tilføj et nyt password[/bright_green]")
            console.print("[bright_green]2. Hent et tidligere gemt password[/bright_green]")
            console.print("[bright_green]3. Slet account/password fra Password Manager[/bright_green]")
            print("\n")
            console.print("[cyan]4. Account indstillinger[/cyan]")
            console.print("[orange3]5. Log ud[/orange3]")
            console.print("[bright_red]6. Exit applikationen[/bright_red]")
            console.print("\n")
            choice = input("Hvad ønsker du at gøre?: ")
            if choice == "1":
                clear_screen()
                while True:
                    if add_service() == "break":
                        clear_screen()
                        break
                    print("\n")
                    user_pick = input("Vil du tilføje flere passwords? (j/n): ")
                    if user_pick == "n":
                        clear_screen()
                        break
                    clear_screen()

            elif choice == "2":
                clear_screen()
                while True:
                    retrieve = retrieve_password()
                    if retrieve is True:
                        print("\n")
                        user_pick = input("Ønsker du at finde et nyt password? (j/n): ")
                        if user_pick == "n":
                            clear_screen()
                            break
                    else:
                        console.print("\n[bold bright_red]Du har ingen gemte passwords.[/bold bright_red]")
                        console.print("[italic]Tryk på en tast for at forsætte.....[/italic]")
                        msvcrt.getch()
                        clear_screen()
                        break

            elif choice == "3":
                clear_screen()
                while True:
                    remove = remove_pass()
                    if remove is True:
                        print("\n")
                        user_pick = input("Ønsker du at fjerne flere passwords? (j/n): ")
                        if user_pick == "n":
                            clear_screen()
                            break
                        clear_screen()
                    else:
                        console.print("\n[bold bright_red]Du har ingen gemte passwords.[/bold bright_red]")
                        console.print("[italic]Tryk på en tast for at forsætte.....[/italic]")
                        msvcrt.getch()
                        clear_screen()
                        break
            elif choice == "4":
                clear_screen()
                while True:
                    console.print(f"[underline]Account indstillinger for {username}:[/underline]")
                    console.print("[italic]Skriv \"b\" i enten username eller password feltet for at afbryde oprettelsen[/italic]")
                    print("\n")
                    console.print("1. Tilføj 2FA (2-Factor-Authentication) til din account")
                    console.print("2. Fjern 2FA fra din account")
                    console.print("3. Slet account")
                    print("\n")
                    settings_choice = input("Hvad ønsker du at gøre?: ")
                    if settings_choice == "1":
                        clear_screen()
                        two_factor_qrcode()
                        break

                    elif settings_choice == "2":
                        clear_screen()
                        remove_tfa()
                        break

                    elif settings_choice == "3":
                        clear_screen()
                        delete_user()
                        break

                    elif settings_choice == "b":
                        clear_screen()
                        break

                    else:
                        console.print("Ikke et gyldigt valg, prøv igen!.")

            elif choice == "5":
                logout()
                clear_screen()

            elif choice == "6":
                logout()
                break

            else:
                clear_screen()
                console.print("[bold bright_red]Dette er ikke en valgmulighed! Vælg en af de opstillede muligheder[/bold bright_red]")
