import sys
import os
import json
import requests
from pathlib import Path
from github import Github
import g4f

sys.path.append(str(Path(__file__).parent.parent.parent))

# GitHub API credentials
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
BOT_GITHUB_TOKEN = os.getenv("BOT")  # Used for approvals
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")
PR_NUMBER = os.getenv("PR_NUMBER")

# Allowed and Forbidden domains
ALLOWED_DOMAINS = {"is-epic.me", "is-awsm.tech"}
FORBIDDEN_DOMAINS = {"is-cool.me", "is-app.tech"}

# PR Review Guidelines
README_RULES = """
### PR Review Guidelines:
1️⃣ **Allowed domains:** Only `is-epic.me` and `is-awsm.tech` are allowed.  
2️⃣ **JSON Structure:** Every file must have `domain`, `subdomain`, `owner`, and `records`.  
3️⃣ **No Wildcard Abuse:** Wildcard (`*.example.com`) requires proper justification.  
4️⃣ **DNS Providers:** Cloudflare (NS), Netlify, and Vercel are **not allowed**.  
5️⃣ **Legal & Appropriate Usage:** Domains must not be used for illegal purposes.  
"""

def fetch_pr(repo):
    """Fetches the PR object."""
    return repo.get_pull(int(PR_NUMBER))

def fetch_changed_files(pr):
    """Gets the list of changed files in the PR."""
    return [file.filename for file in pr.get_files()]

def fetch_file_content(repo, filename, pr):
    """Fetches file content from a PR."""
    try:
        file_content = repo.get_contents(filename, ref=pr.head.ref)
        return file_content.decoded_content.decode()
    except Exception:
        return ""

def check_json_syntax(file_contents):
    """Validates JSON syntax."""
    try:
        json.loads(file_contents)
        return None  # No syntax errors
    except json.JSONDecodeError as e:
        return str(e)  # Return error message

def analyze_file_contents(file_contents):
    """Analyzes the file and finds exact line numbers for issues."""
    issues = []
    lines = file_contents.split("\n")

    for i, line in enumerate(lines, start=1):
        for domain in FORBIDDEN_DOMAINS:
            if domain in line:
                issues.append({
                    "line": i,
                    "issue": f"❌ Forbidden domain `{domain}` found.",
                    "fix": f"Replace `{domain}` with an allowed domain like `is-epic.me` or `is-awsm.tech`."
                })

    return issues

def ai_review_pr(pr_body, changed_files, file_contents):
    """Uses AI to review the PR based on rules."""
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
        - 'Forbidden domain found on line X...'  
        - 'Ensure all fields are present in JSON...'  

    **DO NOT** just say "Request changes"—explain why!
    """

    try:
        response = g4f.ChatCompletion.create(
            model=g4f.models.gpt_4,
            messages=[{"role": "user", "content": review_prompt}]
        )

        decision = response.get("content", "").strip() if isinstance(response, dict) else response.strip()

        if not decision:
            return "request changes", ["AI review failed. Please manually check."]

        if "consider" in decision.lower() or "avoid" in decision.lower():
            return "request changes", decision.split("\n")

        return "approve", []

    except Exception as e:
        return "request changes", [f"AI review failed: {e}"]

def post_line_comment(pr, filename, line, issue, fix):
    """Posts a comment on a specific line in a PR."""
    body = f"**Issue:** {issue}\n**Suggested Fix:** {fix}"
    try:
        # Get the commit object instead of using the SHA string directly
        commit = pr.head.repo.get_commit(pr.head.sha)
        pr.create_review_comment(body, commit, filename, line)
    except Exception as e:
        print(f"Failed to post line comment: {e}")
        # Fallback: post as a general PR comment instead
        pr.create_issue_comment(f"**File:** {filename} (Line {line})\n{body}")

def request_changes(pr, issues, filename):
    """Requests changes on the PR and comments per line."""
    for issue in issues:
        post_line_comment(pr, filename, issue["line"], issue["issue"], issue["fix"])

def approve_pr(pr):
    """Approves the PR using the bot's token."""
    try:
        bot_github = Github(BOT_GITHUB_TOKEN)
        bot_repo = bot_github.get_repo(GITHUB_REPOSITORY)
        bot_pr = bot_repo.get_pull(int(PR_NUMBER))

        bot_pr.create_review(event="APPROVE", body="✅ AI Code Reviewer (Bot) has approved this PR.")
    except Exception as e:
        print(f"Failed to approve PR: {e}")

def main():
    try:
        github = Github(GITHUB_TOKEN)
        repo = github.get_repo(GITHUB_REPOSITORY)
        pr = fetch_pr(repo)

        changed_files = fetch_changed_files(pr)
        all_issues = []

        for file in changed_files:
            file_contents = fetch_file_content(repo, file, pr)
            
            if file.endswith(".json"):
                syntax_error = check_json_syntax(file_contents)
                if syntax_error:
                    all_issues.append({"line": 1, "issue": f"Invalid JSON syntax: {syntax_error}", "fix": "Fix the JSON structure."})

            issues = analyze_file_contents(file_contents)
            if issues:
                all_issues.extend(issues)

        # Get file contents for AI review (use the last file for simplicity)
        file_contents_for_ai = ""
        if changed_files:
            file_contents_for_ai = fetch_file_content(repo, changed_files[-1], pr)

        ai_decision, ai_comments = ai_review_pr(pr.body or "", changed_files, file_contents_for_ai)

        if all_issues or ai_decision == "request changes":
            # Post issues as comments
            for file in changed_files:
                file_issues = [issue for issue in all_issues if True]  # All issues for now
                if file_issues:
                    request_changes(pr, file_issues, file)
            
            # Create a review requesting changes
            review_body = "⚠️ AI Review found issues. See comments for fixes."
            if ai_comments and isinstance(ai_comments, list):
                review_body += "\n\nAdditional AI feedback:\n" + "\n".join(ai_comments)
            
            pr.create_review(event="REQUEST_CHANGES", body=review_body)
        else:
            approve_pr(pr)

    except Exception as e:
        print(f"Script failed with error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()