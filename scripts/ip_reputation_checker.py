import os
import requests
import ipaddress
from dotenv import load_dotenv
from datetime import datetime

def load_api_key():
    """
    Load the AbuseIPDB API key from the .env file.

    Returns:
        str: The API key if found.
        None: If the API key is missing.
    """
    load_dotenv()
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        print("ERROR: ABUSEIPDB_API_KEY was not found in the .env file.")
        return None

    return api_key


def get_verdict(abuse_score):
    """
    Generate a SOC-style verdict based on the AbuseIPDB confidence score.
    """

    if abuse_score >= 80:
        return "HIGH RISK - Investigate immediately"
    elif abuse_score >= 40:
        return "SUSPICIOUS - Review activity"
    elif abuse_score >= 10:
        return "LOW RISK - Monitor if related to alerts"
    else:
        return "CLEAN - No significant abuse reputation"

def save_report(data, verdict):
    """
    Save the IP reputation results to a text report inside the output folder.
    """  
    os.makedirs("output", exist_ok=True)

    report_path = "output/ip_report.txt"

    with open(report_path, "w", encoding="utf-8") as report:
        report.write("========== IP REPUTATION REPORT ==========\n")
        report.write(f"Generated: {datetime.now()}\n\n")
        report.write(f"IP Address      : {data['ipAddress']}\n")
        report.write(f"Country         : {data['countryCode']}\n")
        report.write(f"ISP             : {data['isp']}\n")
        report.write(f"Domain          : {data['domain']}\n")
        report.write(f"Abuse Score     : {data['abuseConfidenceScore']}\n")
        report.write(f"Total Reports   : {data['totalReports']}\n")
        report.write(f"Last Reported   : {data['lastReportedAt']}\n\n")
        report.write(f"Verdict         : {verdict}\n")

    print(f"\nReport saved to: {report_path}")

def is_valid_ip(ip_address):
    """
    Validate whether the user input is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False
    
def check_ip_reputation(ip_address, api_key):
    """
    Query AbuseIPDB for reputation information about a given IP address.
    """
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)

    except requests.exceptions.ConnectionError:
        print("ERROR: Unable to connect to AbuseIPDB. Check your internet connection.")
        return

    except requests.exceptions.Timeout:
        print("ERROR: The request to AbuseIPDB timed out. Try again later.")
        return

    except requests.exceptions.RequestException as error:
        print(f"ERROR: An unexpected request error occurred: {error}")
        return
    if response.status_code == 401:
        print("ERROR 401: Invalid or missing AbuseIPDB API key.")
        return

    if response.status_code == 429:
        print("ERROR 429: API rate limit exceeded. Try again later.")
        return

    if response.status_code >= 500:
        print("ERROR 500: AbuseIPDB server error. Try again later.")
        return

    if response.status_code != 200:
        print(f"ERROR {response.status_code}: Unexpected API response.")
        print(response.text)
        return

    data = response.json()["data"]
    abuse_score = data["abuseConfidenceScore"]
    verdict = get_verdict(abuse_score)
    
    save_report(data, verdict)

    print("\n========== IP REPUTATION REPORT ==========")
    print(f"IP Address        : {data['ipAddress']}")
    print(f"Country           : {data['countryCode']}")
    print(f"ISP               : {data['isp']}")
    print(f"Domain            : {data['domain']}")
    print(f"Abuse Score       : {abuse_score}")
    print(f"Total Reports     : {data['totalReports']}")
    print(f"Last Reported     : {data['lastReportedAt']}")
    print("------------------------------------------")
    print(f"Verdict           : {verdict}")
    print("==========================================\n")


if __name__ == "__main__":
    api_key = load_api_key()

if api_key:
    ip_address = input("Enter IP address: ").strip()

    if not is_valid_ip(ip_address):
        print("ERROR: Invalid IP address format.")
    else:
        check_ip_reputation(ip_address, api_key)