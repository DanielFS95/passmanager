import os
import requests
from rich.console import Console

logged_in_username = None

console = Console()

s = requests.Session()

def clear_screen():
    os.system("cls")