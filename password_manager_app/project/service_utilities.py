import requests
from .auth import check_if_session, s
from tabulate import tabulate
from rich.table import Table
from .common import *


def remove_pass():
    if check_if_session() is False:
        return False

    try:
        r = s.get("https://api.dfsprojekt.dk/user/services/servicelist")
        r.raise_for_status()
    except requests.RequestException:
        print("There was an issue! Please try again later.") 
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

    service_choice = input("\nWhich account do you want to remove?: ")

    if service_choice == "b":
        return "break"

    if service_choice not in servicelist["services"]:
        print("\n")
        console.print(f"\n\n[underline]{service_choice}[/underline] [bold bright_red]is not a saved service. Please choose one of your saved services.[/bold bright_red]\n\n")
        return False

    accounts = servicelist["services"][service_choice]
    if len(accounts) > 1:
        print("\n")
        console.print(f"[italic]Multiple accounts found! A total of {len(accounts)} accounts from the service:[/italic] [underline]{service_choice}[/underline] was found:")
        for account_info in accounts:
            account = account_info["username"]
            console.print(f"[bold]{account}[/bold]")
        chosen_account = input(f"Which account do you wish to remove from {service_choice}?: ")

        userinfo = {"service": service_choice, "account": chosen_account}

    else:
        userinfo = {"service": service_choice}

    try:
        r2 = s.delete("https://api.dfsprojekt.dk/user/services/remove", json=userinfo, headers={"Content-Type": "application/json"},)
        r2.raise_for_status()
        if r2.json().get("status", False):
            print("\n")
            console.print("[bold bright_green]Data was deleted succesfully![/bold bright_green]")
            return True

    except requests.RequestException:
        print("There was an issue. Please try again later.")
        return False


def retrieve_password():
    if not check_if_session():
        return False

    try:
        r = s.get("https://api.dfsprojekt.dk/user/services/servicelist")
        r.raise_for_status()
    except requests.RequestException:
        print("There was an issue. Please try again later.")
        return False

    servicelist = r.json()
    if "services" in servicelist:
        table_data = []
        for service in servicelist["services"]:
            table_data.append([service])
            print
        if len(table_data) == 0:
            return False
        table = tabulate(table_data, headers=["Service"], tablefmt="grid")
        print("\n")
        print(table)

    service_choice = input("\nWhich service do you want to see the password for?: ")

    if service_choice == "b":
        return "break"

    if service_choice not in servicelist["services"]:
        console.print(f"\n\n[underline]{service_choice}[/underline] [bold bright_red]is not a saved service. Please choose a valid service.[/bold bright_red]\n\n")
        return False

    accounts = servicelist["services"][service_choice]
    if len(accounts) > 1:
        console.print(f"[italic]Multiple accounts found! A total of {len(accounts)} accounts from the service:[/italic] [underline]{service_choice}[/underline] was found:")
        for account_info in accounts:
            account = account_info["username"]
            console.print(f"[bold]{account}[/bold]")
        chosen_account = input("\nWhich account do you want to see the password for?: ")
        userinfo = {"service": service_choice, "account": chosen_account}
    else:
        userinfo = {"service": service_choice}

    try:
        headers = {"Content-Type": "application/json"}
        r = s.get("https://api.dfsprojekt.dk/user/services/retrieve", json=userinfo, headers=headers)
    except requests.RequestException:
        print("There was an issue. Please try again later.")
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
                console.print(f"[bold bright_red]PASSWORD LEAK AMOUNT: {password_leak_amount}")
                console.print("[bold bright_red]YOUR PASSWORD WAS FOUND IN A LEAKED DATABASE. YOU SHOULD CHANGE IT AS SOON AS POSSIBLE![/bold bright_red]")
            print("\n\n")
            return True
    except s.exceptions.JSONDecodeError:
        print("There was an issue. Please try again later.")
    return False


def add_service():
    if check_if_session() is False:
        return False

    console.print("[bold cyan]Add a service to the Password Manager[/bold cyan]")
    print("\n")
    console.print("[italic]Enter \"b\" to return to the menu[/italic]")

    service = input("Which service do you want to add?: ")
    if service == "b":
        return "break"
    username = input(f"Enter the username/email that you want to save for {service}: ")
    if username == "b":
        return "break"
    password = input(f"Enter the password that you use with the username/email: {username}: ")
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
            print("There was an issue. Please try again later.")
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
                            console.print(f"\n[yellow]There is currently already a saved password for the user [white underline]{username}[/white underline] on the service [white underline]{service}[/white underline][/yellow]\n")
                            choice = input("Do you want to overwrite the old password with a new one?(y/n): ")
                            if choice == "y":
                                userinfo = {"already_exist": True, "service": service, "username": username, "password": password}
                            else:
                                console.print("[cyan]Your password was not changed.[/cyan]")
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
        console.print(f"[bold bright_green]Success! Your password for [/bold bright_green][underline]{service}[/underline][bold bright_green] for the user [/bold bright_green][underline]{username}[/underline] [bold bright_green]has been added to the Password Manager![/bold bright_green]")
        return True
    
    elif r.json().get("pass_overwritten", False):
        print("\n")
        console.print(f"[bold bright_green]Success! Your password for the account [white underline]{username}[/white underline] for the service [white underline]{service}[/white underline] has been updated![/bold bright_green]")
    
    elif r.json().get("timeout"):
        print("\n")
        console.print("[underline yellow italic] Your session has expired! Please log in again.[/underline yellow italic]")
    
    else:
        print("There was an issue. Please try again later.")
        return False
    


def list_services():
    if check_if_session() is False:
        return False

    try:
        r = s.get("https://api.dfsprojekt.dk/user/services/servicelist")
        r.raise_for_status()
    except requests.RequestException:
        print("There was an issue. Please try again later.")
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
        table = Table(title="You have passwords for the following services:", title_justify="left", title_style="bold", show_lines=True)
        table.add_column("Service", justify="center", no_wrap=True)
        table.add_column("Username/Account", justify="center")
        table.add_column("Password Leak Amount", justify="center")
        for service, account, password_leak_amount in table_data:
            if password_leak_amount > 0:
                leak_amount = f"[red]{password_leak_amount}[/red]"
            else:
                leak_amount = f"[green]{password_leak_amount}[/green]"
            table.add_row(service, account, leak_amount)
        console.print(table)
