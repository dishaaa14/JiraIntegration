import json
import requests

# Your JIRA instance URL and API token
jira_url = "https://dishapanjwani1432-1735014103836.atlassian.net"
jira_email = "dishapanjwani1432@gmail.com"
jira_token = "ATATT3xFfGF0QB1_UBCWTas8kU_Vc4l9aPrBCxmjc0uy17fJW9Kpz1pf2damKagQGclrPhzKInDO7dEx7JXEyUzYEr-qZsXx_SqTbWN6R4c782ydPbaoxxyAFOiZ6scXaNLQ7dp8c44ogIzAiCE5qiWa-vaJazYuyBG0_UA9QLx-W1oqvGtbng0=781FEE09"
jira_project_key = "SCRUM"  # Replace with your project key

# Path to the Snyk JSON report
report_path = 'multi-test-report.json'

# Read the Snyk JSON report
with open(report_path, 'r') as file:
    report = json.load(file)

# Function to create JIRA issues
def create_jira_issue(title, description, severity, cvss_score, cvss, cve_ids):
    # Define the payload for creating an issue in JIRA
    issue_data = {
        "fields": {
            "project": {
                "key": "SCRUM"  # Replace with your JIRA project key
            },
            "summary": f"Security Vulnerability: {title}",
            "description": f"{description}\n\nSeverity: {severity}\nCVSS Score: {cvss_score}\nCVSS v3: {cvss}\nCVE IDs: {cve_ids}",
            "issuetype": {
                "name": "Bug"  # You can modify this based on your JIRA issue types
            },
            "priority": {
                "name": "High" if severity == "high" else "Medium"  # Customize this based on severity
            }
        }
    }

    # Send the request to JIRA to create the issue
    response = requests.post(
        JIRA_URL,
        json=issue_data,
        auth=(JIRA_USERNAME, JIRA_API_TOKEN),
        headers={'Content-Type': 'application/json'}
    )
    
    if response.status_code == 201:
        print(f"Issue created successfully: {title}")
    else:
        print(f"Failed to create issue: {response.status_code} - {response.text}")

# Iterate over the top-level list (each entry represents an issue report)
for entry in report:
    # Get the 'vulnerabilities' from each entry
    vulnerabilities = entry.get('vulnerabilities', [])

    # Iterate over each vulnerability and process it
    for vulnerability in vulnerabilities:
        # Extract the necessary information from the vulnerability
        title = vulnerability.get('title', 'Unknown Title')
        severity = vulnerability.get('severity', 'Unknown Severity')
        description = vulnerability.get('description', 'No Description Provided')
        cvss_score = vulnerability.get('cvssScore', 'N/A')
        cvss = vulnerability.get('CVSSv3', 'N/A')
        cve_ids = ", ".join(vulnerability.get('identifiers', {}).get('CVE', []))

        # Print the extracted data (for debugging, you can later remove this part)
        print(f"Vulnerability Title: {title}")
        print(f"Severity: {severity}")
        print(f"CVSS Score: {cvss_score}")
        print(f"CVSS v3: {cvss}")
        print(f"CVE IDs: {cve_ids}")
        print(f"Description: {description}")
        print("-" * 80)

        # Create JIRA issue using the extracted vulnerability data
        create_jira_issue(title, description, severity, cvss_score, cvss, cve_ids)
