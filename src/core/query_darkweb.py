import requests
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

TOR_PROXY = "socks5h://127.0.0.1:9050"

def query_darkweb(search_term):
    """Search for a term on the dark web using Ahmia (Tor search engine)."""
    url = f"https://ahmia.fi/search/?q={search_term}"
    proxies = {"http": TOR_PROXY, "https": TOR_PROXY}

    try:
        response = requests.get(url, proxies=proxies, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"[ERROR] Dark web search failed: {e}")
        return {"error": "Dark web search failed", "message": str(e)}

if __name__ == "__main__":
    sample_search = "leaked credentials"
    print(query_darkweb(sample_search))
