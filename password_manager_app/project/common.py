import os
import requests
from rich.console import Console
import re


console = Console()

logged_in_username = None

s = requests.Session()

def clear_screen():
    os.system("cls")



def UsernameValidation(username):
    # username is between 4 and 25 characters
    if len(username) < 4 or len(username) > 25 :
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
        console.print("[bold red]Username must not cotain consecutive special chars[/bold red]")
        return False
    
    # contains only letters, numbers and underscore
    valid_grammar = set('abcdefghijklmnopqrstuvwxyzæøå0123456789_-@')

    # checks if all letters/numbers in a username is valid
    for ch in username:
        if ch.lower() not in valid_grammar:
            console.print(f"[bold red]{ch} is not allowed![/bold red]")
            return False

    return True