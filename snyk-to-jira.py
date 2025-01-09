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
with open(report_path, 'r') as report_file:
    report = json.load(report_file)

# Function to create a JIRA issue
def create_jira_issue(vulnerability):
    url = f"{jira_url}/rest/api/3/issue"
    
    # Prepare the JIRA issue data
    issue_data = {
        "fields": {
            "project": {
                "key": jira_project_key
            },
            "summary": f"Vulnerability: {vulnerability['package']}",
            "description": f"Package: {vulnerability['package']}\n" \
                           f"Version: {vulnerability['version']}\n" \
                           f"Severity: {vulnerability['severity']}\n" \
                           f"Description: {vulnerability['description']}",
            "issuetype": {
                "name": "Bug"  # You can change this to "Task" or another issue type if needed
            }
        }
    }

    # Make the API request to create an issue
    response = requests.post(
        url,
        json=issue_data,
        auth=(jira_email, jira_token),
        headers={"Content-Type": "application/json"}
    )

    if response.status_code == 201:
        print(f"Issue created successfully: {vulnerability['package']}")
    else:
        print(f"Failed to create issue: {response.text}")

# Process the Snyk report and create JIRA issues for critical/high vulnerabilities
for issue in report.get('issues', []):
    # Check the severity level of each issue (critical or high)
    if issue['severity'] in ['critical', 'high']:
        create_jira_issue({
            'package': issue['package']['name'],
            'version': issue['package']['version'],
            'severity': issue['severity'],
            'description': issue['title']
        })
