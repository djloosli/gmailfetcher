import configparser # https://docs.python.org/3/library/configparser.html
import argparse # https://docs.python.org/3/library/argparse.html
import os 
import imaplib # https://docs.python.org/3/library/imaplib.html
import email # https://docs.python.org/3/library/email.examples.html
from email.header import decode_header # https://docs.python.org/3/library/email.header.html
import re
from urllib.parse import urlparse # https://docs.python.org/3/library/urllib.parse.html
import whois # ensure whois is installed https://pypi.org/project/python-whois/
import requests
import time	


# Function to connect to Gmail
# Requires IMAP be enabled under IMAP access in Gmail settings
# Requires 2-Step Authentication enabled in Google Account Security settings
# Recommeneded to set up a password under Security > App Passwords
# Edit username and password in config.ini
def connect_to_gmail(username, password):
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(username, password)
        print("Connected to Gmail.")
        return mail
    except Exception as e:
        print("Failed to connect:", e)
        return None

# Place config.ini in the same folder you are running the script from
def list_folders(mail, update_config=False, config_file="config.ini"):
    
    # Lists all available folders in the mailbox.
    # Optionally updates the default folder in config.ini.
    try:
        status, folders = mail.list()
        if status == "OK":
            print("Available folders:")
            folder_names = []
            for folder in folders:
                decoded = folder.decode()
                print(decoded)
                folder_names.append(decoded)

            # Optionally update config.ini
            if update_config:
                print("\nUpdating folder in config.ini...")
                config = configparser.ConfigParser()
                config.read(config_file)
                if "gmail" not in config:
                    config["gmail"] = {}
                config["gmail"]["spam_folder"] = input(
                    "Enter the folder name you want to set for SPAM (as shown above): "
                )
                with open(config_file, "w") as configfile:
                    config.write(configfile)
                print(f"Updated SPAM folder in {config_file}.")

        else:
            print("Failed to list folders.")
    except Exception as e:
        print(f"Error listing folders: {e}")


# Parse and decode emails
def parse_emails(mail):
    print("\n[1] Parsing and decoding emails...")
    mail.select("[Gmail]/Spam") # Select which folder you would like to pull emails from
    _, messages = mail.search(None, "ALL")
    email_ids = messages[0].split()

    parsed_emails = []
    # for email_id in email_ids: # Uncomment/comment to process all emails
    for email_id in email_ids[:10]:  # Limited to 10 for demo purposes
        _, msg_data = mail.fetch(email_id, "(RFC822)")
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else "utf-8")
                from_ = msg.get("From")
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode("utf-8")
                else:
                    body = msg.get_payload(decode=True).decode("utf-8")
                print(f"Subject: {subject}, From: {from_}")
                parsed_emails.append((subject, from_, body))
    return parsed_emails


# Extract links, domains, and IPs
# RFC 822 Message information at https://www.w3.org/Protocols/rfc822/#z26
def extract_links_and_ips(parsed_emails):
    print("\n[2] Extracting links, domains, and IPs...")
    link_pattern = r'(https?://[^\s]+)'
    domains = []
    for subject, from_, body in parsed_emails:
        links = re.findall(link_pattern, body)
        # https://docs.python.org/3/library/urllib.parse.html
        extracted_domains = [urlparse(link).netloc for link in links]
        domains.extend(extracted_domains)
        print(f"Email: {subject}")
        print(f"Links: {links}")
        print(f"Domains: {extracted_domains}")
    return domains


# Perform WHOIS lookups
# https://pypi.org/project/python-whois/
def perform_whois(domains):
    print("\n[3] Performing WHOIS lookups...")
    for domain in domains:
        try:
            w = whois.whois(domain)
            print(f"Domain: {domain}, Registered: {w.creation_date}, Registrar: {w.registrar}")
        except Exception as e:
            print(f"Failed WHOIS for {domain}: {e}")


# Perform reputation checks (e.g., VirusTotal)
# VirusTotal Public API limited to 500 requests per day or 4 requests per minute
# Update request_limit as necessary
def perform_reputation_checks(domains, api_key, request_limit=4):
    print("\n[4] Performing reputation checks...")
    url = "https://www.virustotal.com/vtapi/v2/domain/report"
    requests_made = 0

    for domain in domains:
        if requests_made >= request_limit:
            print(f"Rate limit reached. Sleeping for 60 seconds...")
            time.sleep(60)
            requests_made = 0

        params = {"apikey": api_key, "domain": domain}
        try:
            response = requests.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                print(f"Domain: {domain}")
                print(f"Detected URLs: {data.get('detected_urls', [])}")
            else:
                print(f"Failed to get reputation for {domain}: HTTP {response.status_code}")
            requests_made += 1
        except Exception as e:
            print(f"Error during reputation check for {domain}: {e}")


# Main function to execute selected features
def main():
    parser = argparse.ArgumentParser(description="Email Analyzer")
    parser.add_argument("--username", help="Gmail username")
    parser.add_argument("--password", help="Gmail password or app password")
    parser.add_argument("--config", default="config.ini", help="Path to config file")
    parser.add_argument("--run", default="all", help="Options to run: all or comma-separated list (e.g., 1,3,4)")
    parser.add_argument("--rate-limit", type=int, default=4, help="API request limit per minute (default: 4 for free VirusTotal API)")
    parser.add_argument("--api-key", help="VirusTotal API key (optional; overrides config file)")
    parser.add_argument("--list-folders", action="store_true", help="List all available folders and optionally update the SPAM folder in config.ini.")
    parser.add_argument("--update-config", action="store_true", help="When used with --list-folders, updates the SPAM folder in config.ini.")
    args = parser.parse_args()

    # Load Gmail credentials config.ini formatting:
    # [gmail]
    # username = ******@gmail.com
    # password = **** **** **** ****
    # spam_folder = [Gmail]/Spam
    
    username = args.username
    password = args.password
    if not username or not password:
        config = configparser.ConfigParser()
        config.read(args.config)
        if "gmail" in config:
            username = config["gmail"].get("username")
            password = config["gmail"].get("password")
        else:
            print("No Gmail credentials found.")
            return

    # Connect to Gmail
    mail = connect_to_gmail(username, password)
    if not mail:
        return

    # Handle --list-folders
    if args.list_folders:
        list_folders(mail, update_config=args.update_config, config_file=args.config)
        mail.logout()
        return  # Exit after listing folders

    # Load VirusTotal API key config.ini formatting:
    # [virustotal]
    # api_key = **************************************
    api_key = args.api_key
    if not api_key:
        config = configparser.ConfigParser()
        config.read(args.config)
        if "virustotal" in config:
            api_key = config["virustotal"].get("api_key")
        if not api_key:
            print("No VirusTotal API key found. Provide it via --api-key or config file.")
            return

    # Parse options to run
    options = args.run.split(",")
    parsed_emails = []
    domains = []
    
    # Most options require the emails to be parsed meaning steps 1 and 2 will run regardless
    # Allows for more options to be added and selected
    if "all" in options or "1" in options:
        parsed_emails = parse_emails(mail)

    if "all" in options or "2" in options:
        if not parsed_emails:
            print("[INFO] Running step 1 (Parsing emails) as it's required by step 2.")
            parsed_emails = parse_emails(mail)
        domains = extract_links_and_ips(parsed_emails)

    if "all" in options or "3" in options:
        if not domains:
            if not parsed_emails:
                print("[INFO] Running step 1 (Parsing emails) and step 2 (Extracting domains) as they are required by step 3.")
                parsed_emails = parse_emails(mail)
            print("[INFO] Running step 2 (Extracting domains) as it's required by step 3.")
            domains = extract_links_and_ips(parsed_emails)
        perform_whois(domains)

    if "all" in options or "4" in options:
        if not domains:
            if not parsed_emails:
                print("[INFO] Running step 1 (Parsing emails) and step 2 (Extracting domains) as they are required by step 4.")
                parsed_emails = parse_emails(mail)
            print("[INFO] Running step 2 (Extracting domains) as it's required by step 4.")
            domains = extract_links_and_ips(parsed_emails)
        perform_reputation_checks(domains, api_key, request_limit=args.rate_limit)

    mail.logout()




if __name__ == "__main__":
    main()
