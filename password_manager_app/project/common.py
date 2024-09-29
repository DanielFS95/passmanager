import os
import requests
from rich.console import Console


console = Console()

s = requests.Session()

logged_in_username = None


def clear_screen():
    os.system("cls")
