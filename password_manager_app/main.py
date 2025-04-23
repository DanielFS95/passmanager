from project.auth import check_if_session
from project.handlers import *
from project.common import s
from project.service_utilities import list_services
from project.art import dpm_logo
import time

def logged_out_menu():
    console.print(dpm_logo)
    console.print("[bold yellow]Welcome to Daniels Password Manager (DPM)![/bold yellow]")
    time.sleep(2)
    console.print("[italic]\nLog in or create a new account to use the Password Manager[/italic]")
    console.print("\n[underline green]1. Log in[/underline green]")
    console.print("[underline orange3]2. Create Account[/underline orange3]")
    console.print("[underline red]3. Exit app[/underline red]")
    choice = input("\n\nEnter your choice: ")
    return choice


def logged_in_menu_handler(username):
    console.print(dpm_logo)
    console.print(f"[bold bright_green]Welcome, [/bold bright_green][bold underline bright_green]{username}![/bold underline bright_green]")
    list_services()
    console.print("\n")
    console.print("[underline yellow]You have the following options:[/underline yellow]\n")
    console.print("[bright_green]1. Add a new password[/bright_green]")
    console.print("[bright_green]2. Retrieve a previously saved password[/bright_green]")
    console.print("[bright_green]3. Delete a saved service/password[/bright_green]\n")
    console.print("[cyan]4. Account Settings[/cyan]")
    console.print("[orange3]5. Log out[/orange3]")
    console.print("[bright_red]6. Exit app[/bright_red]\n")
    choice = input("Enter your choice: ")
    return choice


options_start_screen = {
    "1": user_login_handler,
    "2": create_account_handler,
    "3": "exit"
}


logged_in_actions = {
    "1": add_service_handler,
    "2": retrieve_password_handler,
    "3": remove_password_handler,
    "4": account_settings_handler,
    "5": logout_handler,
    "6": "exit_app"
}


if __name__ == "__main__":
    s.cookies.clear()
    logged_in = False
    logged_in_username = None
    while True:
        if not s.cookies:
            choice = logged_out_menu()
            action = options_start_screen.get(choice)

            if action == "exit":
                break
            elif action:
                if action == user_login_handler:
                    logged_in_username = action()
                else:
                    action()

            else:
                clear_screen()
                console.print("[bold bright_red]Not a valid choice! Try again.[/bold bright_red]")

        else:
            if check_if_session() is False:
                break

            logged_in_choice = logged_in_menu_handler(logged_in_username)

            action = logged_in_actions.get(logged_in_choice)
            if action:
                if action == "exit_app":
                    clear_screen()
                    logout()
                    break
                elif action == account_settings_handler:
                    if logged_in_username:
                        action(logged_in_username)
                else:
                    action()
            else:
                clear_screen()
                console.print("[bold bright_red]Not a valid choice! Try again.[/bold bright_red]")
