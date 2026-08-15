import os
import urllib.request

API = os.environ.get("API_BASE", "http://18.171.222.41")


def get(path: str) -> str:
    with urllib.request.urlopen(API + path, timeout=20) as resp:
        return resp.read().decode()


if __name__ == "__main__":
    print(get("/health"))
    print(get("/v1/shipments"))
