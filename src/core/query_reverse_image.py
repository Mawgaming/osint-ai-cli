import webbrowser

def reverse_image_search(image_path):
    """Perform a reverse image search using Google."""
    search_url = f"https://www.google.com/searchbyimage?image_url={image_path}"
    webbrowser.open(search_url)

if __name__ == "__main__":
    sample_image = "https://example.com/profile.jpg"
    reverse_image_search(sample_image)
