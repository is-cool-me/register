import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent.parent))

import g4f
import os
import requests
from github import Github

g4f.debug.logging = True
g4f.debug.version_check = False

GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
GITHUB_REPOSITORY = os.getenv('GITHUB_REPOSITORY')
PR_NUMBER = os.getenv('PR_NUMBER')

# Allowed domains after migration
ALLOWED_DOMAINS = {"is-epic.me", "is-awsm.tech"}

# README rules for validation
README_RULES = """
1. Subdomains must be for personal sites, open-source projects, or legitimate services.
2. JSON structure must contain 'domain', 'subdomain', 'owner', and 'records' fields.
3. If 'proxied' is true, ensure proper justification and compliance with security policies.
4. Wildcard domains (e.g., *.example.is-epic.me) require a detailed reason.
5. Cloudflare (NS), Netlify, and Vercel are not supported.
6. Illegal or inappropriate domain use is strictly prohibited.
7. PR descriptions must be clear, and all required fields must be properly filled.
8. Only the new domains (is-epic.me and is-awsm.tech) are allowed. Old domains will be rejected.
"""

def fetch_changed_files(pr):
    """Fetches the list of files changed in the PR."""
    return [file.filename for file in pr.get_files()]

def fetch_file_content(repo, filename):
    """Fetches the content of a given file in the PR."""
    try:
        file_content = repo.get_contents(filename, ref=pr.head.ref)
        return file_content.decoded_content.decode()
    except Exception as e:
        return f"Error fetching file content: {e}"

def ai_review_pr(pr_body, changed_files, file_contents):
    """Uses AI to review the PR according to README rules."""
    review_prompt = f"""
    Review the following pull request based on these rules:

    {README_RULES}

    PR Description: {pr_body}
    Changed Files: {', '.join(changed_files)}
    
    File Contents:
    {file_contents}

    Check if the PR follows the rules. Approve if everything is correct, or request changes if there are issues. 
    Also, ensure that only the new domains (is-epic.me and is-awsm.tech) are used.
    If old domains (is-cool.me, is-app.tech) are present, reject the PR and request a domain update.
    """

    response = g4f.ChatCompletion.create(model=g4f.models.gpt_4, messages=[{"role": "user", "content": review_prompt}])
    if isinstance(response, dict):
    decision = response.get("content", "").strip().lower()
else:
    print(f"Unexpected response format: {response}")
    decision = response.strip().lower()

    return decision

def post_comment(pr, message):
    """Posts a comment on the PR."""
    pr.create_issue_comment(message)

def main():
    github = Github(GITHUB_TOKEN)
    repo = github.get_repo(GITHUB_REPOSITORY)
    pr = repo.get_pull(int(PR_NUMBER))

    changed_files = fetch_changed_files(pr)
    file_contents = "\n\n".join([f"### {file}\n{fetch_file_content(repo, file)}" for file in changed_files])

    decision = ai_review_pr(pr.body, changed_files, file_contents)

    if "approve" in decision:
        pr.create_review(event="APPROVE", body="AI Code Reviewer has approved this PR.")
        print("PR Approved by AI")
    else:
        pr.create_review(event="REQUEST_CHANGES", body="AI Code Reviewer suggests changes based on README rules.")
        post_comment(pr, f"AI Code Reviewer suggests changes:\n\n{decision}")
        print("PR Needs Changes & Commented")

if __name__ == "__main__":
    main()
