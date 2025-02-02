from project.auth import check_if_session
from project.handlers import *
from project.common import s


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
    "6": "exit_application"
}


if __name__ == "__main__":
    logged_in = False
    while True:
        if not s.cookies:
            choice = start_screen_handler()
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
                print("Du skal være logget ind for at kunne bruge password manageren!")
                break

            logged_in_choice = logged_in_menu_handler()

            action = logged_in_actions.get(logged_in_choice)
            if action:
                if action == "exit_application":
                    clear_screen()
                    logout_handler()
                    break
                else:
                    action()
            else:
                clear_screen()
                console.print("[bold bright_red]Ikke en valgmulighed, prøv igen.[/bold bright_red]")
