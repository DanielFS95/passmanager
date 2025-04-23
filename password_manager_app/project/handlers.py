import msvcrt
from .common import console, clear_screen
from .service_utilities import retrieve_password, add_service, remove_pass
from .auth import pwinput, login,create_user, two_factor_qrcode, logout, delete_user
from .two_factor_auth import remove_tfa
from .art import dpm_logo


def account_settings_menu(username):
    console.print(dpm_logo)
    console.print(f"[underline]Account settings for {username}:[/underline]")
    console.print("[italic]Enter \"b\" to return to the menu[/italic]")
    print("\n")
    console.print("1. Add 2FA (2-Factor-Authentication) to your account (Recommended)")
    console.print("2. Remove 2FA from your account")
    console.print("3. Delete account")
    print("\n")
    choice = input("What is your choice: ")
    return choice


def create_account_handler():
    clear_screen()
    console.print(dpm_logo)
    console.print("[bold cyan]DPM Account Creation[/bold cyan]")
    console.print("[italic]Enter \"b\" to abort and return to the menu[/italic]")
    print("\n")
    account_created = create_user()
    if not account_created:
        console.print("There was an issue! Your account was not created.")

def user_login_handler():
    clear_screen()
    while True:
        console.print(dpm_logo)
        console.print('[bold cyan]Log in with your username and password[/bold cyan]')
        console.print("[italic]Enter \"b\" to return to the menu[/italic]\n")
        username = input("Username: ")
        if username == "b":
            clear_screen()
            break
        password = pwinput.pwinput("Password: ")
        if password == "b":
            clear_screen()
            break
        clear_screen()
        if login(username, password) is True:
            return username
        else:
            console.print("[bold bright_red]Login failed.[/bold bright_red]")


def add_service_handler():
    clear_screen()
    while True:
        console.print(dpm_logo)
        if add_service() == "break":
            clear_screen()
            break
        print("\n")
        user_pick = input("Do you want to add another service/password to the Password Manager? (y/n): ")
        if user_pick == "n":
            clear_screen()
            break
        clear_screen()


def remove_password_handler():
    clear_screen()
    while True:
        console.print(dpm_logo)
        remove = remove_pass()
        if remove is True:
            print("\n")
            user_pick = input("Do you want to remove another service/password from the Password Manager? (y/n): ")
            if user_pick == "n":
                clear_screen()
                break
            clear_screen()

        elif remove == "break":
            clear_screen()
            break

        else:
            console.print("\n[bold bright_red]You currently don't have any passwords saved.[/bold bright_red]")
            console.print("[italic]Press any key to return to the menu.....[/italic]")
            msvcrt.getch()
            clear_screen()
            break


def account_settings_handler(username):
    clear_screen()
    while True:
        account_settings_choice = account_settings_menu(username)
        if account_settings_choice == "1":
            clear_screen()
            two_factor_qrcode(username)
            break

        elif account_settings_choice == "2":
            clear_screen()
            remove_tfa(username)
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
            console.print("Not a valid choice!.")


def retrieve_password_handler():
    clear_screen()
    while True:
        console.print(dpm_logo)
        retrieve = retrieve_password()
        if retrieve is True:
            print("\n")
            user_pick = input("Do you want to retrieve another password? (y/n): ")
            if user_pick == "n":
                clear_screen()
                break

        elif retrieve == "break":
            clear_screen()
            break

        else:
            console.print("\n[bold bright_red]You currently don't have any passwords saved.[/bold bright_red]")
            console.print("[italic]Press any key to return to the menu.....[/italic]")
            msvcrt.getch()
            clear_screen()
            break


def logout_handler():
    logout()
    clear_screen()
