import sys
import os
import time
import requests
from pathlib import Path
from github import Github
import g4f

sys.path.append(str(Path(__file__).parent.parent.parent))

# GitHub API credentials
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # Used for commenting and requesting changes
BOT_GITHUB_TOKEN = os.getenv("BOT")  # Used for approvals
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")
PR_NUMBER = os.getenv("PR_NUMBER")

# Allowed domains after migration
ALLOWED_DOMAINS = {"is-epic.me", "is-awsm.tech"}

# PR Review Rules
README_RULES = """
### PR Review Guidelines
1. **Subdomains must be valid**: Only for personal sites, open-source projects, or legitimate services.
2. **JSON Structure**: Each file must contain `domain`, `subdomain`, `owner`, and `records`.
3. **No Wildcard Abuse**: Wildcard domains (`*.example.com`) require proper justification.
4. **Disallowed DNS Providers**: Cloudflare (NS), Netlify, and Vercel are **not allowed**.
5. **Legal & Appropriate Usage**: Domains must not be used for illegal or inappropriate purposes.
6. **Clear Descriptions**: PR descriptions should explain why the domain is needed.
7. **Domain Restrictions**: **Only `is-epic.me` and `is-awsm.tech`** are allowed.
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
    **Task:** Review this Pull Request based on the following rules:

    {README_RULES}

    **PR Description:**  
    {pr_body}  

    **Changed Files:**  
    {', '.join(changed_files)}

    **File Contents:**  
    {file_contents}

    ---
    
    **Expected Output Format:**
    - If the PR is correct, respond with:  
      ✅ PR Approved. No issues found.  
    - If issues exist, respond with:
      - **Structured comments per issue.**
      - **GitHub Actions-style comments**, e.g.:  
        - 'Consider handling session failures...'  
        - 'Avoid using a generic exception handler...'  
        - 'Ensure that the import statement for `BlackboxAPI` aligns with others...'  

    **DO NOT** just say "Request changes"—explain why!
    """

    try:
        response = g4f.ChatCompletion.create(
            model=g4f.models.gpt_4,
            messages=[{"role": "user", "content": review_prompt}]
        )

        decision = response.get("content", "").strip() if isinstance(response, dict) else response.strip()

        # If AI fails or response is empty, request changes automatically
        if not decision:
            print("❌ AI response is empty or invalid. Defaulting to 'request changes'.")
            return "request changes", ["AI review failed. Please manually check."]

        # If AI finds issues, extract structured comments
        if "consider" in decision.lower() or "avoid" in decision.lower():
            return "request changes", decision.split("\n")

        return "approve", []

    except Exception as e:
        print(f"❌ AI review failed: {e}")
        return "request changes", ["AI review failed. Please manually check."]

def post_comment(pr, message):
    """Posts a comment on the PR."""
    pr.create_issue_comment(message)

def approve_pr(repo, pr):
    """Approves the PR using the bot's personal GitHub token."""
    bot_github = Github(BOT_GITHUB_TOKEN)
    bot_repo = bot_github.get_repo(GITHUB_REPOSITORY)
    bot_pr = bot_repo.get_pull(int(PR_NUMBER))

    bot_pr.create_review(event="APPROVE", body="✅ AI Code Reviewer (Bot) has approved this PR.")
    print("✅ PR Approved by AI (Using Bot Token)")

def request_changes(repo, pr, comments):
    """Requests changes on the PR using the default GitHub Actions token."""
    formatted_comments = "\n\n".join([f"⚠️ **{comment}**" for comment in comments])
    pr.create_review(event="REQUEST_CHANGES", body=f"⚠️ AI Review suggests changes:\n\n{formatted_comments}")
    post_comment(pr, f"⚠️ AI Review:\n\n{formatted_comments}")
    print("⚠️ PR Needs Changes")

def main():
    github = Github(GITHUB_TOKEN)
    repo = github.get_repo(GITHUB_REPOSITORY)
    pr = repo.get_pull(int(PR_NUMBER))

    changed_files = fetch_changed_files(pr)
    file_contents = "\n\n".join([f"### {file}\n{fetch_file_content(repo, file)}" for file in changed_files])

    decision, comments = ai_review_pr(pr.body, changed_files, file_contents)

    if decision == "approve":
        approve_pr(repo, pr)  # Uses bot token for approval
    elif decision == "request changes":
        request_changes(repo, pr, comments)  # Uses GitHub Actions token for requests

if __name__ == "__main__":
    main()
