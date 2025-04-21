import msvcrt
from project import common
from .common import console, clear_screen
from .service_utilities import retrieve_password, add_service, remove_pass, delete_user
from .auth import pwinput, login,create_user, two_factor_qrcode, logout
from .two_factor_auth import remove_tfa


logged_in_username = None


def account_settings_menu():
    username = common.logged_in_username
    console.print(f"[underline]Account indstillinger for {username}:[/underline]")
    console.print("[italic]Skriv \"b\" i enten username eller password feltet for at afbryde oprettelsen[/italic]")
    print("\n")
    console.print("1. Tilføj 2FA (2-Factor-Authentication) til din account")
    console.print("2. Fjern 2FA fra din account")
    console.print("3. Slet account")
    print("\n")
    choice = input("Hvad ønsker du at gøre?: ")
    return choice


def create_account_handler():
    clear_screen()
    console.print("[bold cyan]Opret en konto for at bruge Daniels Password Manager.[/bold cyan]")
    console.print("[italic]Skriv \"b\" i enten username eller password feltet for at afbryde oprettelsen[/italic]")
    print("\n")
    account_created = create_user()
    if not account_created:
        console.print("Der opstod et problem, og din account blev ikke oprettet!")

def user_login_handler():
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
            return
        else:
            console.print("[bold bright_red]Login mislykkedes![/bold bright_red]")


def add_service_handler():
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


def remove_password_handler():
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

        elif remove == "break":
            clear_screen()
            break

        else:
            console.print("\n[bold bright_red]Du har ingen gemte passwords.[/bold bright_red]")
            console.print("[italic]Tryk på en tast for at forsætte.....[/italic]")
            msvcrt.getch()
            clear_screen()
            break


def account_settings_handler():
    username = common.logged_in_username
    clear_screen()
    while True:
        account_settings_choice = account_settings_menu()
        if account_settings_choice == "1":
            clear_screen()
            two_factor_qrcode()
            break

        elif account_settings_choice == "2":
            clear_screen()
            remove_tfa()
            print()
            break

        elif account_settings_choice == "3":
            clear_screen()
            delete_user(username)
            break

        elif account_settings_choice == "b":
            clear_screen()
            break

        else:
            clear_screen()
            console.print("Ikke et gyldigt valg, prøv igen!.")


def retrieve_password_handler():
    clear_screen()
    while True:
        retrieve = retrieve_password()
        if retrieve is True:
            print("\n")
            user_pick = input("Ønsker du at finde et nyt password? (j/n): ")
            if user_pick == "n":
                clear_screen()
                break

        elif retrieve == "break":
            clear_screen()
            break

        else:
            console.print("\n[bold bright_red]Du har ingen gemte passwords.[/bold bright_red]")
            console.print("[italic]Tryk på en tast for at forsætte.....[/italic]")
            msvcrt.getch()
            clear_screen()
            break


def logout_handler():
    logout()
    clear_screen()
