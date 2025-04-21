from project.auth import check_if_session
from project.handlers import *
from project.common import s, list_services


def logged_out_menu():
    console.print("[bold yellow]Velkommen til Daniel's Password Manager![/bold yellow]")
    console.print("[italic]\nLog ind eller opret en konto for at bruge Password Manageren[/italic]")
    console.print("\n[underline green]1. Log ind[/underline green]")
    console.print("[underline orange3]2. Opret account[/underline orange3]")
    console.print("[underline red]3. Exit applikationen[/underline red]")
    choice_start = input("\n\nHvad ønsker du at gøre?: ")
    return choice_start


def logged_in_menu_handler():
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
    while True:
        if not s.cookies:
            choice = logged_out_menu()
            action = options_start_screen.get(choice)

            if action == "exit":
                break
            elif action:
                if action == user_login_handler:
                    username = action()
                else:
                    action()

            else:
                clear_screen()
                console.print("[bold bright_red]Ikke en valgmulighed, prøv igen.[/bold bright_red]")

        else:
            if check_if_session() is False:
                break

            logged_in_choice = logged_in_menu_handler()

            action = logged_in_actions.get(logged_in_choice)
            if action:
                if action == "exit_app":
                    clear_screen()
                    logout()
                    break
                else:
                    action()
            else:
                clear_screen()
                console.print("[bold bright_red]Ikke en valgmulighed, prøv igen.[/bold bright_red]")
