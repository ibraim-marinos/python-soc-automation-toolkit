import pandas as pd
import os
from datetime import datetime


def save_report(report_content):
    """
    Save the failed login analysis report to a text file.
    """

    os.makedirs("output", exist_ok=True)

    report_path = "output/failed_login_report.txt"

    with open(report_path, "w", encoding="utf-8") as report:
        report.write(report_content)

    print(f"\nReport saved to: {report_path}")

def main():
    """
    Entry point for the Windows Failed Login Parser.
    """

    log_data = pd.read_csv("sample_data/failed_logins.csv")
    report_content = ""
    failed_logins = log_data[log_data["EventID"] == 4625]

    for _, event in failed_logins.iterrows():

        username = event["TargetUserName"]
        source_ip = event["IpAddress"]
        failure_reason = event["FailureReason"]
        computer = event["Computer"]
        time = event["TimeCreated"]
        event_report = (
            "========== FAILED LOGIN ==========\n"
            f"User           : {username}\n"
            f"Source IP      : {source_ip}\n"
            f"Failure Reason : {failure_reason}\n"
            f"Computer       : {computer}\n"
            f"Time           : {time}\n"
            "==================================\n\n"
        )

        report_content += event_report

        print("========== FAILED LOGIN ==========")
        print(f"User           : {username}")
        print(f"Source IP      : {source_ip}")
        print(f"Failure Reason : {failure_reason}")
        print(f"Computer       : {computer}")
        print(f"Time           : {time}")
        print("==================================\n")

    total_failed_logins = len(failed_logins)                   
    unique_users = failed_logins["TargetUserName"].unique()
    unique_source_ips = failed_logins["IpAddress"].unique()

    print("========== SUMMARY ==========")
    print(f"Total Failed Logins : {total_failed_logins}")

    print("\nUnique Users:")
    for user in unique_users:
        print(f"- {user}")

    print("\nUnique Source IPs:")
    for ip in unique_source_ips:
        print(f"- {ip}")

    print("=============================\n")

    report_content += (
        "========== SUMMARY ==========\n"
        f"Total Failed Logins : {total_failed_logins}\n\n"
    )

    report_content += "Unique Users:\n"

    for user in unique_users:
        report_content += f"- {user}\n"

    report_content += "\nUnique Source IPs:\n"

    for ip in unique_source_ips:
        report_content += f"- {ip}\n"

    report_content += "\n"

    user_counts = failed_logins["TargetUserName"].value_counts()

    print("========== FAILED LOGIN COUNTS ==========")

    report_content += "========== FAILED LOGIN COUNTS ==========\n"

    for user, count in user_counts.items():
        print(f"{user} : {count} attempts")
        report_content += f"{user} : {count} attempts\n"


    report_content += "\n"

    print("=========================================\n")

    brute_force_threshold = 5

    print("========== BRUTE FORCE DETECTION ==========")

    for user, count in user_counts.items():
        if count >= brute_force_threshold:    
            print(f"User           : {user}")
            print(f"Failed Logins  : {count}")
            print("Severity       : HIGH")
            print("Confidence     : HIGH")
            print("MITRE ATT&CK   : T1110 - Brute Force")
            print("Verdict        : Possible Brute Force Attack")
            print("------------------------------------------")

            print("===========================================\n")
            
            report_content += (

                "========== BRUTE FORCE DETECTION ==========\n"
                f"User           : {user}\n"
                f"Failed Logins  : {count}\n"
                "Severity       : HIGH\n"
                "Confidence     : HIGH\n"
                "MITRE ATT&CK   : T1110 - Brute Force\n"
                "Verdict        : Possible Brute Force Attack\n"
                  "------------------------------------------\n"
                  "===========================================\n\n"
            )
            
    save_report(report_content)   

if __name__ == "__main__":
    main()
