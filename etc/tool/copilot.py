import sys
import os
import time
import requests
from pathlib import Path
from github import Github
import g4f

sys.path.append(str(Path(__file__).parent.parent.parent))

# GitHub API credentials
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")
PR_NUMBER = os.getenv("PR_NUMBER")

# Allowed domains after migration
ALLOWED_DOMAINS = {"is-epic.me", "is-awsm.tech"}

# PR Review Rules
README_RULES = """
1. Subdomains must be for personal sites, open-source projects, or legitimate services.
2. JSON must contain 'domain', 'subdomain', 'owner', and 'records'.
3. Wildcard domains require justification.
4. Cloudflare (NS), Netlify, and Vercel are not supported.
5. Illegal or inappropriate domain use is prohibited.
6. PR descriptions must be clear.
7. Only new domains (is-epic.me and is-awsm.tech) are allowed.
"""

def fetch_changed_files(pr):
    """Fetches the list of files changed in the PR."""
    return [file.filename for file in pr.get_files()]

def fetch_file_content(repo, filename):
    """Fetches file content from a PR."""
    try:
        file_content = repo.get_contents(filename, ref=pr.head.ref)
        return file_content.decoded_content.decode()
    except Exception as e:
        return f"Error fetching file content: {e}"

def ai_review_pr(pr_body, changed_files, file_contents):
    """Uses AI to review the PR based on the rules."""
    review_prompt = f"""
    Review the PR based on these rules:

    {README_RULES}

    PR Description: {pr_body}
    Changed Files: {', '.join(changed_files)}

    File Contents:
    {file_contents}

    - Approve if all rules are met.
    - Reject if old domains (`is-cool.me`, `is-app.tech`) are used.
    - If the JSON structure is missing or incorrect, request changes.
    """

    try:
        response = g4f.ChatCompletion.create(
            model=g4f.models.gpt_4,
            messages=[{"role": "user", "content": review_prompt}]
        )
        
        # Ensure response is a string
        decision = response.get("content", "").strip().lower() if isinstance(response, dict) else response.strip().lower()

        # Log unexpected responses
        if not decision:
            print("❌ AI response is empty or invalid. Defaulting to 'request changes'.")
            return "request changes"

        # Force rejection if old domains are detected
        if "is-cool.me" in file_contents or "is-app.tech" in file_contents:
            print("❌ PR rejected due to use of old domains.")
            return "reject"

        return decision

    except Exception as e:
        print(f"❌ AI review failed: {e}")
        return "request changes"

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
        pr.create_review(event="APPROVE", body="✅ AI Code Reviewer has approved this PR.")
        print("✅ PR Approved by AI")
    elif "reject" in decision:
        pr.create_review(event="REQUEST_CHANGES", body="❌ PR rejected due to rule violations.")
        post_comment(pr, "❌ Your PR violates the domain rules (e.g., using `is-cool.me`). Please update and resubmit.")
        print("❌ PR Rejected")
    else:
        pr.create_review(event="REQUEST_CHANGES", body="⚠️ AI Code Reviewer suggests changes.")
        post_comment(pr, "⚠️ AI Reviewer suggests changes:\n\n" + decision)
        print("⚠️ PR Needs Changes")

if __name__ == "__main__":
    main()
