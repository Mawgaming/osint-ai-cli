import requests
import logging

# Configure logging
logging.basicConfig(level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")

SOCIAL_MEDIA_PLATFORMS = {
    "twitter": "https://twitter.com/{}",
    "github": "https://github.com/{}",
    "instagram": "https://www.instagram.com/{}",
    "reddit": "https://www.reddit.com/user/{}",
    "linkedin": "https://www.linkedin.com/in/{}"
}

def query_username(username):
    """Search for a username on social media platforms."""
    results = {}

    for platform, url in SOCIAL_MEDIA_PLATFORMS.items():
        full_url = url.format(username)
        
        try:
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200:
                results[platform] = full_url
            else:
                results[platform] = "Not found"
        except requests.exceptions.RequestException:
            results[platform] = "Not found"

    return results

if __name__ == "__main__":
    sample_username = "testuser"
    print(query_username(sample_username))

