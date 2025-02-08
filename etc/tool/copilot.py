import sys
import os
import json
import requests
import time
from pathlib import Path
from github import Github
import g4f  # Assuming you're using g4f for AI responses

sys.path.append(str(Path(__file__).parent.parent.parent))

# 🔒 GitHub API Credentials
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # Used for commenting & requesting changes
BOT_GITHUB_TOKEN = os.getenv("BOT")  # Used for approvals
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")
PR_NUMBER = os.getenv("PR_NUMBER")

# 🚫 Disallowed Domains
DISALLOWED_DOMAINS = {"is-cool.me", "is-app.tech"}
# ✅ Allowed Domains
ALLOWED_DOMAINS = {"is-epic.me", "is-awsm.tech"}

# 📌 PR Review Rules
README_RULES = """
### PR Review Guidelines
1. **Valid Subdomains**: Only for personal sites, open-source projects, or legitimate services.
2. **Correct JSON Structure**: Must include `domain`, `subdomain`, `owner`, and `records` fields.
3. **No Wildcard Abuse**: `*.example.com` requires proper justification.
4. **Disallowed DNS Providers**: Cloudflare (NS), Netlify, and Vercel are **not allowed**.
5. **Legal & Appropriate Use**: Domains must not be used for illegal or inappropriate purposes.
6. **Clear PR Descriptions**: Should explain why the subdomain is needed.
7. **Domain Restrictions**: Only `is-epic.me` and `is-awsm.tech` are allowed.
"""

# 📌 Function: Fetch Changed Files
def fetch_changed_files(pr):
    """Fetches the list of changed files in the PR."""
    return [file.filename for file in pr.get_files()]

# 📌 Function: Fetch File Content
def fetch_file_content(repo, filename, pr):
    """Fetches file content from a PR."""
    try:
        file_content = repo.get_contents(filename, ref=pr.head.ref)
        return file_content.decoded_content.decode()
    except Exception as e:
        return f"Error fetching file content: {e}"

# 📌 Function: Check JSON Syntax
def check_json_syntax(file_contents):
    """Validates JSON format."""
    try:
        json.loads(file_contents)
        return True, None  # Valid JSON
    except json.JSONDecodeError as e:
        return False, str(e)  # Return syntax error

# 📌 Function: AI PR Review
def ai_review_pr(pr_body, changed_files, file_contents):
    """Uses AI to review the PR based on the guidelines."""

    # 🚨 **HARD-CODED CHECK FOR OLD DOMAINS**
    if any(domain in pr_body or domain in file_contents for domain in DISALLOWED_DOMAINS):
        return "request changes", ["🚫 This PR contains a **forbidden domain** (`is-cool.me` or `is-app.tech`). Only `is-epic.me` or `is-awsm.tech` are allowed."]

    # 🚨 **CHECK JSON SYNTAX**
    is_valid_json, json_error = check_json_syntax(file_contents)
    if not is_valid_json:
        return "request changes", [f"⚠️ JSON Syntax Error: {json_error}. Please fix and resubmit."]

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

    **DO NOT** just say "Request changes"—explain why!
    """

    try:
        response = g4f.ChatCompletion.create(
            model=g4f.models.gpt_4,
            messages=[{"role": "user", "content": review_prompt}]
        )

        decision = response.get("content", "").strip() if isinstance(response, dict) else response.strip()

        # 🚨 Safety Check: If AI fails, request changes
        if not decision:
            return "request changes", ["AI review failed. Please manually check."]

        # 🚨 If AI finds issues, reject PR
        if "consider" in decision.lower() or "avoid" in decision.lower():
            return "request changes", decision.split("\n")

        return "approve", []

    except Exception as e:
        return "request changes", [f"AI review failed: {e}. Please manually check."]

# 📌 Function: Post Comment on PR
def post_comment(pr, message):
    """Posts a comment on the PR."""
    pr.create_issue_comment(message)

# 📌 Function: Approve PR
def approve_pr():
    """Approves the PR using the bot's GitHub token."""
    bot_github = Github(BOT_GITHUB_TOKEN)
    bot_repo = bot_github.get_repo(GITHUB_REPOSITORY)
    bot_pr = bot_repo.get_pull(int(PR_NUMBER))

    bot_pr.create_review(event="APPROVE", body="✅ AI Code Reviewer (Bot) has approved this PR.")
    print("✅ PR Approved by AI (Using Bot Token)")

# 📌 Function: Request Changes on PR
def request_changes(pr, comments):
    """Requests changes using the default GitHub Actions token."""
    formatted_comments = "\n\n".join([f"⚠️ **{comment}**" for comment in comments])
    pr.create_review(event="REQUEST_CHANGES", body=f"⚠️ AI Review suggests changes:\n\n{formatted_comments}")
    post_comment(pr, f"⚠️ AI Review:\n\n{formatted_comments}")
    print("⚠️ PR Needs Changes")

# 📌 Main Function
def main():
    github = Github(GITHUB_TOKEN)
    repo = github.get_repo(GITHUB_REPOSITORY)
    pr = repo.get_pull(int(PR_NUMBER))

    changed_files = fetch_changed_files(pr)
    file_contents = "\n\n".join([f"### {file}\n{fetch_file_content(repo, file, pr)}" for file in changed_files])

    # 🚀 Run AI Review
    decision, comments = ai_review_pr(pr.body, changed_files, file_contents)

    if decision == "approve":
        approve_pr()  # Uses bot token for approval
    elif decision == "request changes":
        request_changes(pr, comments)  # Uses GitHub Actions token for requests

if __name__ == "__main__":
    main()
