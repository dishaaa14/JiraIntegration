import requests
import json
import os

# Environment Variables
SNYK_API_URL = "https://snyk.io/api/v1"
SNYK_TOKEN = os.getenv('6e8051e6-4678-42f4-8363-117db9521bef')
JIRA_BASE_URL = os.getenv('https://dishapanjwani1432-1735014103836.atlassian.net')
JIRA_USER = os.getenv('dishapanjwani1432')
JIRA_API_TOKEN = os.getenv('ATATT3xFfGF0obAB5hyKJHNh-1ihbM1wu383NUZfYUnUrYX__Q8EMJRd5nc1rM7-RvdulZaib695arE7zuB_WyLcKVmpzHXukpt4Q9JOF88XGkhP-NRCwWzSs-90gP6BDYmC9BTjDYP_GXnkKsmWy7NCuXGVJeiDEP1gb61d63g4AwqQqUeHLW0=38542C71')

def fetch_snyk_vulnerabilities():
    headers = {
        'Authorization': f'token {SNYK_TOKEN}',
        'Content-Type': 'application/json'
    }
    response = requests.get(f'{SNYK_API_URL}/orgs/<your-org-id>/projects', headers=headers)
    
    if response.status_code == 200:
        projects = response.json().get('projects', [])
        for project in projects:
            project_id = project['id']
            vulns_response = requests.get(f'{SNYK_API_URL}/orgs/<your-org-id>/projects/{project_id}/issues', headers=headers)
            if vulns_response.status_code == 200:
                issues = vulns_response.json().get('issues', {}).get('vulnerabilities', [])
                for issue in issues:
                    if issue['severity'] in ['high', 'critical']:
                        create_jira_issue(issue)
            else:
                print(f"Failed to fetch vulnerabilities for project {project_id}: {vulns_response.status_code}")
    else:
        print(f"Failed to fetch projects: {response.status_code}")

def create_jira_issue(issue):
    jira_api_url = f"{JIRA_BASE_URL}/rest/api/3/issue"
    auth = (JIRA_USER, JIRA_API_TOKEN)
    headers = {
        'Content-Type': 'application/json'
    }

    issue_data = {
        "fields": {
            "project": {
                "key": "<your-project-key>"
            },
            "summary": f"[{issue['severity'].capitalize()}] {issue['title']}",
            "description": f"{issue['description']}\n\nAffected Package: {issue['packageName']}\nSeverity: {issue['severity'].capitalize()}",
            "issuetype": {
                "name": "Bug"
            },
            "priority": {
                "name": issue['severity'].capitalize()
            }
        }
    }

    response = requests.post(jira_api_url, auth=auth, headers=headers, data=json.dumps(issue_data))

    if response.status_code == 201:
        print(f"Issue created successfully: {response.json().get('key')}")
    else:
        print(f"Failed to create issue: {response.status_code} {response.text}")

if __name__ == "__main__":
    fetch_snyk_vulnerabilities()
