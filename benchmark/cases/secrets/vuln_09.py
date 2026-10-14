# CWE-798: Hardcoded GitHub personal access token
# Vulnerability: a GitHub PAT is embedded as a string literal

import urllib.request
import json


# VULNERABLE: GitHub PAT — "ghp_" prefix is detected by secrets scanners
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
GITHUB_API   = "https://api.github.com"


def github_request(endpoint):
    """Make a request to the GitHub API using the hardcoded token."""
    req = urllib.request.Request(
        f"{GITHUB_API}/{endpoint}",
        headers={
            "Authorization": f"token {GITHUB_TOKEN}",  # VULNERABLE
            "Accept":        "application/vnd.github.v3+json",
            "User-Agent":    "MyApp/1.0",
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def list_repos(org):
    """List repositories in an organisation."""
    return github_request(f"orgs/{org}/repos")


def get_user():
    """Get the authenticated user info — authenticates with hardcoded token."""
    return github_request("user")


def create_issue(owner, repo, title, body):
    """Create an issue using the hardcoded PAT."""
    data = json.dumps({"title": title, "body": body}).encode()
    req = urllib.request.Request(
        f"{GITHUB_API}/repos/{owner}/{repo}/issues",
        data=data,
        headers={
            "Authorization": f"token {GITHUB_TOKEN}",
            "Content-Type":  "application/json",
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


if __name__ == "__main__":
    print(f"Token: {GITHUB_TOKEN[:8]}...")
