#!/usr/bin/env python3

import requests
import Levenshtein
import pyfiglet
from colorama import init, Fore, Style  # BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE.
import os
import time

# Initialize colorama
init(autoreset=True)

# Google Safe Browsing API key (avoid hardcoding in production - use environment variables or secure storage)
API_KEY = 'AIzaSyDrgKLC7BJos0lmdpsqLapCREfjgBB5IQg'

# Load phishing domains and URLs from files
def load_data(file_name, description):
    try:
        with open(file_name, 'r') as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}Error: {description} file '{file_name}' not found.")
        return []

PHISHING_DOMAINS = load_data('/usr/local/bin/ALL-phishing-domains.txt', 'Phishing Domains')
PHISHING_URLS = load_data('/usr/local/bin/ALL-phishing-links.txt', 'Phishing Links')

# Phishing-related keywords
PHISHING_KEYWORDS = [
    'login', 'verify', 'account', 'update', 'secure', 'ebayisapi',
    'signin', 'banking', 'password'
]

# Commonly impersonated domains
SUSPICIOUS_DOMAINS = [
    'facebook.com', 'google.com', 'paypal.com', 'amazon.com',
    'bankofamerica.com', 'twitter.com', 'instagram.com', 'linkedin.com',
    'microsoft.com', 'apple.com', 'netflix.com', 'yahoo.com', 'bing.com',
    'adobe.com', 'dropbox.com', 'github.com', 'salesforce.com', 'uber.com',
    'airbnb.com', 'spotify.com', 'ebay.com', 'alibaba.com', 'walmart.com',
    'target.com', 'bestbuy.com', 'chase.com', 'citibank.com', 'wellsfargo.com',
    'hulu.com', 'tiktok.com', 'reddit.com', 'pinterest.com', 'quora.com',
    'medium.com', 'whatsapp.com', 'wechat.com', 'snapchat.com', 'tumblr.com',
    'vimeo.com', 'dailymotion.com'
]

def is_phishing_url(url):
    """
    Check if the given URL is a phishing link.
    """
    # Direct match against known phishing URLs
    if url in PHISHING_URLS:
        return True

    # Check if the URL contains any known phishing domains
    for domain in PHISHING_DOMAINS:
        if domain in url:
            return True

    # Use Google Safe Browsing API for additional checks
    if API_KEY and check_with_google_safe_browsing(url):
        return True

    # Check for suspicious keywords
    if any(keyword in url.lower() for keyword in PHISHING_KEYWORDS):
        return True

    # Check against commonly impersonated domains using Levenshtein distance
    for domain in SUSPICIOUS_DOMAINS:
        if url.lower() == domain:
            return False  # Exact match to a trusted domain is safe
        if Levenshtein.distance(url.lower(), domain) < 5:  # Similarity threshold
            return True

    # URL considered safe if none of the checks matched
    return False

def check_with_google_safe_browsing(url):
    """
    Use Google Safe Browsing API to check the URL.
    """
    safe_browsing_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}'
    payload = {
        "client": {
            "clientId": "PhishingDetector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    for attempt in range(3):  # Retry logic with a maximum of 3 attempts
        try:
            response = requests.post(safe_browsing_url, json=payload, timeout=10)
            response.raise_for_status()
            result = response.json()
            return 'matches' in result
        except requests.exceptions.RequestException as e:
            print(f"{Fore.YELLOW}Warning: Error checking URL with Google Safe Browsing API: {e}")
            time.sleep(2)  # Wait before retrying
    print(f"{Fore.YELLOW}Google Safe Browsing API check failed multiple times.")
    return False

def check_bulk_urls(urls):
    """
    Check a list of URLs for phishing.
    """
    results = []
    for url in urls:
        url = url.strip()
        if not (url.startswith("http://") or url.startswith("https://")):
            if "." in url:
                url = "https://" + url  # Default to HTTPS if no protocol provided
            else:
                results.append(f"{Fore.RED}Invalid URL: {url}")
                continue

        # Check the URL
        if is_phishing_url(url):
            results.append(f"{Fore.RED}Phishing detected 🚩: {url}")
        else:
            results.append(f"{Fore.GREEN}Safe URL ✅: {url}")
    return results

def main():
    """
    Main program logic for the phishing URL detector.
    """
    # Display ASCII art
    ascii_art = pyfiglet.figlet_format("PHISH-DETECT", font="slant")
    print(f"{Fore.BLUE}{Style.BRIGHT}{ascii_art}")

    # Display metadata
    print(f"{Fore.RED}Version: 1.1\n")
    print(f"{Fore.GREEN}Created by {Style.BRIGHT}@Hijaab{Style.RESET_ALL}{Fore.GREEN}.\n")

    while True:
        # Prompt user for input (single or bulk URLs)
        input_mode = input("Enter 'single' for a single URL or 'bulk' for bulk URLs (or press 'q' to quit): ").strip().lower()

        if input_mode == 'q':
            print("Exiting the tool. Goodbye!")
            break

        if input_mode == 'single':
            url = input("Enter the URL to check 🔍: ").strip()
            if not (url.startswith("http://") or url.startswith("https://")):
                if "." in url:
                    url = "https://" + url  # Default to HTTPS if no protocol provided
                else:
                    print(f"{Fore.RED}Invalid URL. Please try again.")
                    continue

            # Check the URL
            if is_phishing_url(url):
                print(f"{Fore.RED}Phishing detected 🚩: {url}")
            else:
                print(f"{Fore.GREEN}Safe URL ✅: {url}")

        elif input_mode == 'bulk':
            # User inputs URLs directly for bulk check
            urls = input("Enter the URLs to check, separated by commas: ").split(',')
            urls = [url.strip() for url in urls if url.strip()]

            if not urls:
                print(f"{Fore.RED}No URLs provided. Please try again.")
                continue

            results = check_bulk_urls(urls)
            print("\n".join(results))

        else:
            print(f"{Fore.RED}Invalid choice. Please enter 'single' or 'bulk'.")

if __name__ == "__main__":
    main()
