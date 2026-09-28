import requests

def fetch_data():
    response = requests.get("https://api.github.com")
    return response.json()

if __name__ == "__main__":
    fetch_data()
