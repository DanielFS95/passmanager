import requests
from .auth import check_if_session, s
from tabulate import tabulate
from .common import *


def list_services():
    if check_if_session() is False:
        console.print("[bold bright_red]Du skal være logget ind først![/bold bright_red]")
        return False

    try:
        r = s.get("https://api.dfsprojekt.dk/user/services/servicelist")
        r.raise_for_status()
    except requests.RequestException:
        print("Der opstod en fejl. Prøv igen senere.")
        return False

    servicelist = r.json()
    if "services" in servicelist:
        table_data = []
        for service, accounts in servicelist["services"].items():
            for account_info in accounts:
                account = account_info["username"]
                password_leak_amount = account_info["password_leak_amount"]
                if password_leak_amount is None:
                    password_leak_amount = 0
                table_data.append([service, account, password_leak_amount])
        table = tabulate(table_data, headers=["Service", "Username/Account", "Password Leak Count"], tablefmt="grid")
        console.print("\n[bold]Du har passwords for følgende services:[/bold]")
        print(table)


def remove_pass():
    if check_if_session() is False:
        console.print("[bold bright_red]Du skal være logget ind først![/bold bright_red]")
        return False

    try:
        r = s.get("https://api.dfsprojekt.dk/user/services/servicelist")
        r.raise_for_status()
    except requests.RequestException:
        print("Der opstod en fejl. Prøv igen senere.")
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

    if service_choice == "b":
        return "break"

    if service_choice not in servicelist["services"]:
        print("\n")
        console.print(f"\n\n[underline]{service_choice}[/underline] [bold bright_red]er ikke en gemt service. Vælg venligst en gyldig service.[/bold bright_red]\n\n")
        return False

    accounts = servicelist["services"][service_choice]
    if len(accounts) > 1:
        print("\n")
        console.print(f"[italic]Der blev fundet {len(accounts)} accounts fra servicen[/italic] [underline]{service_choice}[/underline]:")
        for account_info in accounts:
            account = account_info["username"]
            console.print(f"[bold]{account}[/bold]")
        chosen_account = input(f"Hvilken account ønsker du at fjerne fra {service_choice}?: ")

        userinfo = {"service": service_choice, "account": chosen_account}

    else:
        userinfo = {"service": service_choice}

    try:
        r2 = s.delete("https://api.dfsprojekt.dk/user/services/remove", json=userinfo, headers={"Content-Type": "application/json"},)
        r2.raise_for_status()
        if r2.json().get("status", False):
            print("\n")
            console.print("[bold bright_green]Dine oplysninger blev slettet succesfuldt![/bold bright_green]")
            return True

    except requests.RequestException:
        print("Der opstod en fejl. Prøv igen senere.")
        return False


def retrieve_password():
    if not s.cookies:
        console.print("[bold bright_red]Du skal være logget ind først![/bold bright_red]")
        return False

    try:
        r = s.get("https://api.dfsprojekt.dk/user/services/servicelist")
        r.raise_for_status()
    except requests.RequestException:
        print("Der opstod et problem! Prøv igen senere!")
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

    if service_choice == "b":
        return "break"

    if service_choice not in servicelist["services"]:
        console.print(f"\n\n[underline]{service_choice}[/underline] [bold bright_red]er ikke en gemt service. Vælg venligst en gyldig service.[/bold bright_red]\n\n")
        return False

    accounts = servicelist["services"][service_choice]
    if len(accounts) > 1:
        console.print(f"\n[italic]Der blev fundet {len(accounts)} accounts fra servicen[/italic] [underline]{service_choice}[/underline]:")
        for account_info in accounts:
            account = account_info["username"]
            console.print(f"[bold]{account}[/bold]")
        chosen_account = input("\nHvilken account ønsker du at se password for?: ")
        userinfo = {"service": service_choice, "account": chosen_account}
    else:
        userinfo = {"service": service_choice}

    try:
        headers = {"Content-Type": "application/json"}
        r = s.get("https://api.dfsprojekt.dk/user/services/retrieve", json=userinfo, headers=headers)
    except requests.RequestException:
        print("Der opstod en fejl. Prøv igen senere.")
        return False

    try:
        jsondata = r.json()
        if "username" and "password" in jsondata:
            username = jsondata["username"]
            password = jsondata["password"]
            if "password_leak_amount" in jsondata:
                password_leak_amount = jsondata["password_leak_amount"]
            else:
                password_leak_amount = 0

            console.print(f"\n\n[bold]Username/Email:[/bold] [underline]{username}[/underline]")
            console.print(f"[bold]Password:[/bold] [underline]{password}[/underline]")
            if password_leak_amount > 0:
                console.print(f"[bold bright_red]PASSWORD LEAK ANTAL: {password_leak_amount}")
                console.print("[bold bright_red]DIT PASSWORD BLEV FUNDET I ET DATALEAK! DU BØR ÆNDRE DIT PASSWORD HURTIGST MULIGT![/bold bright_red]")
            print("\n\n")
            return True
    except s.exceptions.JSONDecodeError:
        print("Der opstod en fejl. Prøv igen senere.")
    return False


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
        except requests.RequestException:
            print("Der opstod en fejl!")
            return False

        servicelist = r.json()
        if "services" in servicelist:
            for saved_service, accounts in servicelist["services"].items():
                if service.lower() == saved_service.lower():
                    service_found = True
                    for account_info in accounts:
                        account = account_info["username"]
                        if username.lower() == account.lower():
                            account_found = True
                            console.print(f"\n[yellow]Der er allerede gemt et password for [white underline]{username}[/white underline] ved servicen [white underline]{service}[/white underline][/yellow]\n")
                            choice = input("Ønsker du at overskrive det tidligere gemte password?(j/n): ")
                            if choice == "j":
                                userinfo = {"already_exist": True, "service": service, "username": username, "password": password}
                            else:
                                console.print("[red]Dit password blev ikke ændret![/red]")
                                return False
                    if not account_found:
                        userinfo = {"service": service, "username": username, "password": password}
                        break

            if not service_found:
                userinfo = {"service": service, "username": username, "password": password}

    headers = {"Content-Type": "application/json"}
    r = s.post("https://api.dfsprojekt.dk/user/services/add", json=userinfo, headers=headers)
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
    
    else:
        console.print("[bold bright_red]Der skete en fejl![/bold bright_red]")
        return False
