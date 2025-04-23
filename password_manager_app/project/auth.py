import requests
import pwinput
from password_validator import PasswordValidator
from .common import console, clear_screen, s
from .two_factor_auth import two_factor_qrcode
import re
import time
from .art import dpm_logo

validatepass = PasswordValidator()
validatepass\
    .min(10)\
    .has().uppercase()\
    .has().lowercase()\
    .has().digits()\
    .no().spaces()


def login(username, password):
    login_info = {"username": username, "password": password}
    r = s.post("https://api.dfsprojekt.dk/account/login", json=login_info, headers={"Content-Type": "application/json"})

    if r.status_code == 200 and r.json().get("success"):
        console.print("[bold green]Success! You will now be logged in![/bold green]")
        time.sleep(1)
        clear_screen()
        return True
    elif r.status_code == 200 and r.json().get("get_tfa_code"):
        username = r.json().get("username")
        console.print(dpm_logo)
        console.print("[italic cyan]Enter the 2FA-Code from the authenticator app on your phone[/italic cyan]\n")
        tfa_code = input("2FA-Code: ")
        jsondata = {"tfa_code": tfa_code, "username": username}
        r = s.post("https://api.dfsprojekt.dk/tfa/check-tfa", json=jsondata, headers={"Content-Type": "application/json"})
        if r.status_code == 200 and r.json().get("tfa-success"):
            console.print("[bold green]Success! You will now be logged in![/bold green]")
            time.sleep(1)
            clear_screen()
            return True
        
    return False


def create_user():
    while True:
        console.print("[bold green]Please choose a username for your DPM account.[/bold green]")
        username = input("username: ")
        if username == "b":
            clear_screen()
            return True

        if not username_validation(username):
            continue

        # Check if the username is available
        if not check_username(username):
            console.print("[bold bright_red]Username is already taken! Try something else.[/bold bright_red]")
            continue
        clear_screen()


        while True:
            print("\n")
            console.print(f"[bold orange3]Please choose a password for the account:[/bold orange3] [bold cyan]{username}[/bold cyan]\n")
            print("\n")
            time.sleep(1)
            console.print(f"[italic white]Your password must be at least [/italic white][bold underline red]10 characters long[/bold underline red][italic white] and must contain [/italic white][bold underline red]both uppercase and lowercase letters[/bold underline red][italic white], as well as [/italic white][bold underline red]at least one number[/bold underline red][italic white].[/italic white]\n")
            password = pwinput.pwinput(f"Please enter the password you want use for your account: ")
            if password == "b":
                clear_screen()
                return True
            elif not validatepass.validate(password):
                console.print("[bold bright_red]Your password does not meet the requirements! Please choose a new one.[/bold bright_red]")
                continue
            password_confirm = pwinput.pwinput("Confirm your password: ")
            if password_confirm == "b":
                clear_screen()
                return True
            if password != password_confirm:
                console.print("[bold bright_red]Your passwords do not match. Please try again.[/bold bright_red]")
                continue
            break

        # Send registration request
        userinfo = {"username": username, "password": password}
        headers = {"Content-Type": "application/json"}
        try:
            r = s.put("https://api.dfsprojekt.dk/account/register", json=userinfo, headers=headers)
            r.raise_for_status()  # Ensure the request was successful
        except requests.RequestException:
            console.print(f"[bold bright_red]An error occurred while creating your account[/bold bright_red]")
            return False
        
        if r.json().get("username_error"):
            console.print("[bold red]That username is already taken![/bold red]")
            
        # Check if the account was created successfully
        if r.json().get("Account_created", False):
            clear_screen()
            console.print(f"[bold bright_green]Your account with the username[/bold bright_green] [underline]{username}[/underline][bold bright_green] was created successfully![/bold bright_green]")
            print("\n")
            user_tfa_choice = input("Do you want to add 2FA(Two Factor Authentication) to your account? (Recommended) (y/n): ")
            if user_tfa_choice.lower() == "y":
                if two_factor_qrcode(username):
                    clear_screen()
                    console.print(f"[bold green]2FA was added for the account: {username}![/bold green]")
                else:
                    clear_screen()
                    console.print("[bold bright_red]There was an issue during 2FA-Setup. Please try again later, or contact the developer for support![/bold bright_red]")
                    return False
            else:
                clear_screen()
                console.print("[italic]You chose to opt out of 2FA. Remember you can always add it to your account through the account settings menu.[/italic]")
                print("\n")
            return True
        else:
            console.print("[bold bright_red]There was an issue during account creation. Please try again later or contact the developer for support.[/bold bright_red]")
            return False
        

def delete_user(username):
    while True:
        last_choice = input("Are you absolutely sure you want to delete your account and all its data? This action cannot be undone after it is performed!(y/n): ")
        if last_choice == "n":
            clear_screen()
            return
        elif last_choice == "y":
            clear_screen()
            break
        else:
            clear_screen()
            print("Invalid input. Please confirm your choice of deleting your account by typing 'y' or 'n'.")
            continue

    console.print("[underline]To delete your account, you need to confirm with your Password and 2FA (if 2FA is enabled)[/underline]")
    password = pwinput.pwinput("Enter your password: ")

    headers = {"Content-Type": "application/json"}
    jsondata = {"username": username, "password": password}

    r = s.post("https://api.dfsprojekt.dk/user/accountdelete", json=jsondata, headers=headers)
    if r.status_code == 200 and r.json().get("tfa_confirm"):
        username = r.json().get("username")
        tfa_code = input("Enter your 2FA-Code: ")
        jsondata = {"tfa_code": tfa_code, "username": username}

        r = s.post("https://api.dfsprojekt.dk/user/accountdelete", json=jsondata, headers=headers)
        if r.status_code == 200 and r.json().get("delete_complete"):
            clear_screen()
            console.print("Your account and its data has been deleted!")

        else:
            print("There was an issue. Your account was not deleted. Please try again later or contact the developer for support.")

    elif r.status_code == 200 and r.json().get("delete_complete"):
        clear_screen()
        console.print("Your account and its data has been deleted!")


def check_if_session():
    if not s.cookies:
        console.print("[bold bright_red]You need to be logged in first![/bold bright_red]")
        return False
    return True


def logout():
    if check_if_session() is False:
        return False
    try:
        r = s.post("https://api.dfsprojekt.dk/account/logout", headers={"Content-Type": "application/json"})
        if r.status_code == 200:
            print("You have been logged out!")
            s.cookies.clear()
    except requests.RequestException:
        print(f"Tnere was an issue during logout.")


def check_username(username):
    headers = {"Content-Type": "application/json"}
    params = {"username": username}
    t = s.get("https://api.dfsprojekt.dk/user/username/availability", params=params, headers=headers)
    return t.json().get("available", False)



def username_validation(username):
    # username is between 4 and 25 characters
    if len(username) < 4 or len(username) > 25:
        console.print("[bold red]Username must be between 4 and 25 characters![/bold red]")
        return False
    
    # doesn't contain any whitespaces
    if re.search(r'\s', username):
        console.print("[bold red]Username must not contain any whitespaces![/bold red]")
        return False
    
    # ends with a letter or a number.
    if not username[-1].isalnum():
        console.print("[bold red]Username must end with a letter or number[/bold red]")
        return False

    # doesn't contain consecutive special chars
    if re.search(r'_{2,}|-{2,}|@{2,}', username):
        console.print("[bold red]Username must not contain consecutive special chars[/bold red]")
        return False
    
    # contains only letters, numbers and underscore
    valid_grammar = set('abcdefghijklmnopqrstuvwxyzæøå0123456789_-@')

    # checks if all letters/numbers in a username is valid
    for ch in username:
        if ch.lower() not in valid_grammar:
            console.print(f"[bold red]The character '{ch}' is not allowed in the username![/bold red]")
            return False

    return True