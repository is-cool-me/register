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


def wait_for_workflows(repo, pr_number, max_wait=1800, interval=30):
    """Waits for specified GitHub workflows to complete."""
    workflows = ["auto-merge.yml", "save-pr-number.yml", "validation.yml"]
    start_time = time.time()

    while time.time() - start_time < max_wait:
        runs = repo.get_workflow_runs(branch=f"refs/pull/{pr_number}/merge", status="in_progress")
        if all(run.name not in workflows for run in runs):
            return True  # All workflows completed
        
        time.sleep(interval)

    print("❌ Workflows did not complete within the time limit.")
    return False

import os
import requests

def approve_pull_request(repo, pr_number):
    """Approves the pull request using GitHub token if available, otherwise fallback to standard API."""
    pr = repo.get_pull(pr_number)

    # Dismiss previous approvals first
    dismiss_previous_approvals(repo, pr_number)

    # Validate PR files and domains, collect feedback comments
    comments = []
    
    if not validate_pr_files(pr):
        comments.append({"file": "unknown", "line": 0, "comment": "❌ PR contains invalid files. Please review file requirements."})
    
    if not validate_domains(pr):
        comments.append({"file": "unknown", "line": 0, "comment": "❌ PR includes an invalid domain. Ensure compliance with domain policies."})

    # Wait for workflows to complete
    if not wait_for_workflows(repo, pr_number):
        comments.append({"file": "unknown", "line": 0, "comment": "❌ Workflows did not pass successfully. Please check GitHub Actions."})

    # Post review comments if any issues are found
    if comments:
        post_review_comment(repo, pr_number, comments)
        return

    # Attempt to approve PR using GitHub Actions secret token
    github_token = os.getenv("GITHUB_TOKEN")
    if github_token:
        headers = {"Authorization": f"token {github_token}"}
        approval_url = f"https://api.github.com/repos/{repo.owner.login}/{repo.name}/pulls/{pr_number}/reviews"
        data = {"event": "APPROVE", "body": "✅ PR approved automatically as it complies with rules and all workflow checks passed."}
        
        response = requests.post(approval_url, json=data, headers=headers)
        if response.status_code in [200, 201]:
            print("✅ PR approved successfully using GitHub token.")
            return
        else:
            print(f"⚠️ GitHub token approval failed: {response.json()}")

    # Fallback: Approve using repository API
    try:
        pr.create_review(event="APPROVE", body="✅ PR approved automatically as it complies with rules and all workflow checks passed.")
        print("✅ PR approved successfully using repository API.")
    except Exception as e:
        print(f"❌ Failed to approve PR using repository API: {e}")

def dismiss_previous_approvals(repo, pr_number):
    """Dismisses previous approvals for the PR."""
    pr = repo.get_pull(pr_number)
    reviews = pr.get_reviews()

    for review in reviews:
        if review.state == "APPROVED":
            repo._requester.requestJson("PUT", f"{pr.url}/reviews/{review.id}/dismissals",
                                        input={"message": "Approval dismissed due to new commit."})
            print(f"⚠️ Previous approval by {review.user.login} dismissed.")

def post_review_comment(repo, pr_number, comments):
    """Posts review comments on the PR instead of rejecting it outright."""
    pr = repo.get_pull(pr_number)

    review_comments = [{"path": c["file"], "position": c["line"], "body": c["comment"]} for c in comments]
    if review_comments:
        pr.create_review(event="REQUEST_CHANGES", comments=review_comments)
        print("⚠️ Review comments posted for required changes.")
    else:
        print("✅ No issues found.")
