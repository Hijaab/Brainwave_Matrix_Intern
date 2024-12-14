#!/usr/bin/env python3

import requests
import Levenshtein
import pyfiglet
from colorama import init, Fore, Style #BLACK , RED , GREEN , YELLOW , BLUE , MAGENTA , CYAN , WHITE.
import os

# Initialize colorama
init(autoreset=True)

# Google Safe Browsing API key (ensure this is your actual key)
API_KEY = 'AIzaSyCv2Dgt1tX3XFfZFu7P9OqdsEqtcc4_16I'

# Load phishing domains and URLs from files
def load_data(file_name, description):
    try:
        with open(file_name, 'r') as f:
            return [line.strip() for line in f.readlines()]
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

    try:
        response = requests.post(safe_browsing_url, json=payload)
        response.raise_for_status()
        result = response.json()

        if 'matches' in result:
            return True

    except requests.exceptions.RequestException as e:
        print(f"{Fore.YELLOW}Warning: Error checking URL with Google Safe Browsing API: {e}")
        if e.response:
            print(f"Response: {e.response.text}")  # Print the detailed error response

    # Check for suspicious keywords
    for keyword in PHISHING_KEYWORDS:
        if keyword in url.lower():
            return True

    # Check against commonly impersonated domains
    for domain in SUSPICIOUS_DOMAINS:
        if url.lower() == domain:
            return False  # Exact match to a trusted domain is safe
        if Levenshtein.distance(url.lower(), domain) < 5:  # Similarity threshold
            return True

    # URL considered safe if none of the checks matched
    return False

def generate_report(url, is_phishing):
    """
    Generate a simple report for the detected URL.
    """
    report_path = 'phishing_report.txt'
    status = "Phishing" if is_phishing else "Safe"
    
    with open(report_path, 'a') as report_file:
        report_file.write(f"URL: {url}\nStatus: {status}\n\n")
    
    print(f"{Fore.GREEN}Report generated: {report_path}")

def main():
    """
    Main program logic for the phishing URL detector.
    """
    # Display ASCII art
    ascii_art = pyfiglet.figlet_format("PHISH-DETECT", font="slant")
    print(f"{Fore.RED}{Style.BRIGHT}{ascii_art}")

    # Display metadata
    print(f"{Fore.BLUE}Version: 1.0\n")
    print(f"{Fore.GREEN}Created by {Style.BRIGHT}@Hijaab{Style.RESET_ALL}{Fore.GREEN}.\n")

    while True:
        # Prompt user for input
        url = input("Enter the URL to check (or press 'q' to quit): ").strip()

        # Exit condition
        if url.lower() == 'q':
            print("Exiting the tool. Goodbye!")
            break

        # Ensure proper URL format
        if not (url.startswith("http://") or url.startswith("https://")):
            if "." in url:
                url = "https://" + url  # Default to HTTPS if no protocol provided
            else:
                print(f"{Fore.RED}Invalid URL. Please try again.")
                continue

        # Check the URL
        is_phishing = is_phishing_url(url)

        if is_phishing:
            print(f"{Fore.RED}Phishing detected 🚩: {url}")
        else:
            print(f"{Fore.GREEN}Safe URL ✅: {url}")

        # Generate a report for the URL
        generate_report(url, is_phishing)

if __name__ == "__main__":
    main()
