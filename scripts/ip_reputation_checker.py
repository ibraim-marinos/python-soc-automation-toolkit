import os
import json
import csv
import requests
import ipaddress
from dotenv import load_dotenv
from datetime import datetime

def load_api_key():
    """
    Load the API keys from the .env file.

    Returns:
        tuple: (AbuseIPDB API key, VirusTotal API key)
    """

    load_dotenv()

    abuse_api_key = os.getenv("ABUSEIPDB_API_KEY")
    virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not abuse_api_key:
        print("ERROR: ABUSEIPDB_API_KEY was not found in the .env file.")
        return None, None

    if not virustotal_api_key:
        print("ERROR: VIRUSTOTAL_API_KEY was not found in the .env file.")
        return None, None

    return abuse_api_key, virustotal_api_key


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

def get_combined_verdict(abuse_score, malicious, suspicious):
    """
    Generate a combined SOC verdict using AbuseIPDB and VirusTotal results.
    """

    if malicious > 0 or abuse_score >= 80:
        return "MALICIOUS - Immediate investigation recommended"

    if suspicious > 0 or abuse_score >= 40:
        return "SUSPICIOUS - Review activity and correlate with logs"

    return "CLEAN - No significant threat indicators found"

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

def save_json_report(report_data):
    """
    Save the combined report to a JSON file.
    """

    os.makedirs("output", exist_ok=True)

    with open("output/ip_report.json", "w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4)

def save_csv_report(report_data):
    """
    Save the combined report to a CSV file.
    """

    os.makedirs("output", exist_ok=True)

    with open("output/ip_report.csv", "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow([
            "ip_address",
            "abuse_score",
            "abuse_verdict",
            "vt_malicious",
            "vt_suspicious",
            "vt_harmless",
            "vt_reputation",
            "combined_verdict"
        ])

        writer.writerow([
            report_data["ip_address"],
            report_data["abuseipdb"]["abuse_score"],
            report_data["abuseipdb"]["verdict"],
            report_data["virustotal"]["malicious"],
            report_data["virustotal"]["suspicious"],
            report_data["virustotal"]["harmless"],
            report_data["virustotal"]["reputation"],
            report_data["combined_verdict"]
        ])

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

    return {
    "abuse_score": abuse_score,
    "verdict": verdict
}

def check_virustotal_ip(ip_address, api_key):
    """
    Query VirusTotal for reputation information about a given IP address.
    """

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)

    except requests.exceptions.ConnectionError:
        print("ERROR: Unable to connect to VirusTotal. Check your internet connection.")
        return

    except requests.exceptions.Timeout:
        print("ERROR: The request to VirusTotal timed out. Try again later.")
        return

    except requests.exceptions.RequestException as error:
        print(f"ERROR: An unexpected request error occurred: {error}")
        return

    if response.status_code == 401:
        print("ERROR 401: Invalid or missing VirusTotal API key.")
        return

    if response.status_code == 429:
        print("ERROR 429: VirusTotal API rate limit exceeded. Try again later.")
        return

    if response.status_code >= 500:
        print("ERROR 500: VirusTotal server error. Try again later.")
        return

    if response.status_code != 200:
        print(f"ERROR {response.status_code}: Unexpected VirusTotal API response.")
        print(response.text)
        return

    data = response.json()["data"]

    attributes = data["attributes"]
    analysis = attributes["last_analysis_stats"]

    malicious = analysis["malicious"]
    suspicious = analysis["suspicious"]
    harmless = analysis["harmless"]

    reputation = attributes["reputation"]

    print("\n========== VIRUSTOTAL REPORT ==========")
    print(f"Malicious     : {malicious}")
    print(f"Suspicious    : {suspicious}")
    print(f"Harmless      : {harmless}")
    print(f"Reputation    : {reputation}")
    print("=======================================\n")

    return {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "reputation": reputation
            }

if __name__ == "__main__":
    abuse_api_key, virustotal_api_key = load_api_key()

    if abuse_api_key and virustotal_api_key:
        ip_address = input("Enter IP address: ")

        abuse_result = check_ip_reputation(ip_address, abuse_api_key)
        vt_result = check_virustotal_ip(ip_address, virustotal_api_key)
        combined_verdict = get_combined_verdict(
            abuse_result["abuse_score"],
            vt_result["malicious"],
            vt_result["suspicious"]
        )

        print("\n========== COMBINED SOC VERDICT ==========")
        print(combined_verdict)
        print("==========================================\n")

        report_data = {
            "ip_address": ip_address,

            "abuseipdb": abuse_result,

            "virustotal": vt_result,

            "combined_verdict": combined_verdict
        }

        save_json_report(report_data)
        save_csv_report(report_data)