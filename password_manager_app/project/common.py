import os
import requests
from rich.console import Console
from tabulate import tabulate
from project.auth import check_if_session


logged_in_username = None

console = Console()

s = requests.Session()

def clear_screen():
    os.system("cls")


def list_services():
    if check_if_session() is False:
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