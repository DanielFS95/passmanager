import os
import requests
from rich.console import Console


console = Console()

s = requests.Session()

def clear_screen():
    os.system("cls")
