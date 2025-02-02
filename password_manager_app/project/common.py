import os
import requests
from rich.console import Console


console = Console()

logged_in_username = None

s = requests.Session()

def clear_screen():
    os.system("cls")
