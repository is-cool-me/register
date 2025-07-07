import sys
import os
import json
import requests
from pathlib import Path
from github import Github
import g4f
import re

sys.path.append(str(Path(__file__).parent.parent.parent))

# GitHub API credentials
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
BOT_GITHUB_TOKEN = os.getenv("BOT")  # Used for approvals
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")
PR_NUMBER = os.getenv("PR_NUMBER")

# Domain configuration
ALLOWED_DOMAINS = {"is-epic.me", "is-awsm.tech"}
FORBIDDEN_DOMAINS = {"is-cool.me", "is-app.tech"}
RESERVED_SUBDOMAINS = {"www", "api", "mail", "ftp", "admin", "root", "test", "staging", "dev"}
FORBIDDEN_DNS_PROVIDERS = {
    "ns1.vercel-dns.com", "ns2.vercel-dns.com",
    "dns1.p01.nsone.net", "dns2.p01.nsone.net",
    "dns1.registrar-servers.com", "dns2.registrar-servers.com"
}

# Comprehensive PR Review Guidelines
DOMAIN_RULES = """
### Domain Registration Review Guidelines:

**🎯 ALLOWED DOMAINS:**
- ✅ `is-epic.me` and `is-awsm.tech` ONLY
- ❌ `is-cool.me` and `is-app.tech` are FORBIDDEN (migrated domains)

**📋 REQUIRED JSON STRUCTURE:**
```json
{
    "domain": "is-epic.me",
    "subdomain": "example",
    "owner": {
        "username": "github-username",
        "email": "valid@email.com"
    },
    "records": {
        "A": ["1.1.1.1"],
        "CNAME": "example.com"
    },
    "proxied": false
}
```

**🚫 FORBIDDEN CONTENT:**
- Illegal activities, hate speech, malware
- Copyright infringement, spam, phishing
- Adult content without proper age verification
- Cryptocurrency mining, illegal gambling

**🔧 DNS RESTRICTIONS:**
- ❌ Cloudflare NS records (ns1.cloudflare.com, etc.)
- ❌ Netlify hosting (*.netlify.app)
- ❌ Vercel hosting (*.vercel.app)
- ✅ GitHub Pages, custom servers, other providers OK

**📝 NAMING RULES:**
- Subdomain must be 3-63 characters
- Only lowercase letters, numbers, hyphens
- Cannot start/end with hyphen
- No reserved names (www, api, mail, etc.)

**🔍 VALIDATION CHECKS:**
- Valid email format required
- GitHub username should exist
- DNS records must be properly formatted
- No wildcard abuse without justification
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

def validate_json_structure(data, filename):
    """Validates the JSON structure for domain registration."""
    issues = []
    
    # Required fields
    required_fields = ["domain", "subdomain", "owner", "records"]
    for field in required_fields:
        if field not in data:
            issues.append({
                "line": 1,
                "issue": f"❌ Missing required field: '{field}'",
                "fix": f"Add the '{field}' field to your JSON structure"
            })
    
    # Domain validation
    if "domain" in data:
        if data["domain"] not in ALLOWED_DOMAINS:
            issues.append({
                "line": 1,
                "issue": f"❌ Invalid domain: '{data['domain']}'",
                "fix": f"Use only allowed domains: {', '.join(ALLOWED_DOMAINS)}"
            })
    
    # Subdomain validation
    if "subdomain" in data:
        subdomain = data["subdomain"]
        if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", subdomain):
            issues.append({
                "line": 1,
                "issue": f"❌ Invalid subdomain format: '{subdomain}'",
                "fix": "Use only lowercase letters, numbers, and hyphens (3-63 chars)"
            })
        
        if subdomain in RESERVED_SUBDOMAINS:
            issues.append({
                "line": 1,
                "issue": f"❌ Reserved subdomain: '{subdomain}'",
                "fix": f"Choose a different subdomain. Reserved: {', '.join(RESERVED_SUBDOMAINS)}"
            })
        
        if len(subdomain) < 3 or len(subdomain) > 63:
            issues.append({
                "line": 1,
                "issue": f"❌ Subdomain length invalid: {len(subdomain)} characters",
                "fix": "Subdomain must be 3-63 characters long"
            })
    
    # Owner validation
    if "owner" in data:
        owner = data["owner"]
        if not isinstance(owner, dict):
            issues.append({
                "line": 1,
                "issue": "❌ Owner field must be an object",
                "fix": "Use format: {\"username\": \"...\", \"email\": \"...\"}"
            })
        else:
            if "email" not in owner:
                issues.append({
                    "line": 1,
                    "issue": "❌ Missing owner email",
                    "fix": "Add a valid email address in owner.email"
                })
            elif not re.match(r"^[^@]+@[^@]+\.[^@]+$", owner.get("email", "")):
                issues.append({
                    "line": 1,
                    "issue": f"❌ Invalid email format: '{owner.get('email', '')}'",
                    "fix": "Provide a valid email address"
                })
            
            if "username" not in owner:
                issues.append({
                    "line": 1,
                    "issue": "❌ Missing GitHub username",
                    "fix": "Add your GitHub username in owner.username"
                })
    
    # Records validation
    if "records" in data:
        records = data["records"]
        if not isinstance(records, dict) or not records:
            issues.append({
                "line": 1,
                "issue": "❌ Records field must be a non-empty object",
                "fix": "Add at least one DNS record (A, AAAA, CNAME, etc.)"
            })
        else:
            # Check for forbidden DNS providers
            if "NS" in records:
                for ns in records["NS"]:
                    if any(forbidden in ns for forbidden in FORBIDDEN_DNS_PROVIDERS):
                        issues.append({
                            "line": 1,
                            "issue": f"❌ Forbidden DNS provider: '{ns}'",
                            "fix": "Use allowed DNS providers (not Cloudflare NS, Vercel, etc.)"
                        })
            
            # Check for forbidden hosting providers
            if "CNAME" in records:
                cname = records["CNAME"]
                if "netlify.app" in cname or "vercel.app" in cname:
                    issues.append({
                        "line": 1,
                        "issue": f"❌ Forbidden hosting provider: '{cname}'",
                        "fix": "Use GitHub Pages, custom servers, or other allowed providers"
                    })
            
            # Validate IP addresses
            if "A" in records:
                for ip in records["A"]:
                    if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
                        issues.append({
                            "line": 1,
                            "issue": f"❌ Invalid IPv4 address: '{ip}'",
                            "fix": "Provide valid IPv4 addresses in A records"
                        })
    
    # Proxied validation
    if "proxied" in data and not isinstance(data["proxied"], bool):
        issues.append({
            "line": 1,
            "issue": "❌ Proxied field must be true or false",
            "fix": "Set proxied to either true or false"
        })
    
    return issues

def check_file_naming(filename):
    """Validates the filename follows the correct pattern."""
    issues = []
    
    if not filename.startswith("domains/"):
        return issues
    
    # Extract subdomain and domain from filename
    basename = os.path.basename(filename)
    if not basename.endswith(".json"):
        issues.append({
            "line": 1,
            "issue": f"❌ File must have .json extension",
            "fix": "Rename file to end with .json"
        })
        return issues
    
    # Check naming pattern: subdomain.domain.json
    name_parts = basename[:-5].split(".")  # Remove .json
    if len(name_parts) < 3:
        issues.append({
            "line": 1,
            "issue": f"❌ Invalid filename format: '{basename}'",
            "fix": "Use format: subdomain.domain.json (e.g., example.is-epic.me.json)"
        })
    
    return issues

def analyze_file_contents(file_contents, filename):
    """Comprehensive analysis of domain registration file."""
    issues = []
    
    # Check JSON syntax
    try:
        data = json.loads(file_contents)
    except json.JSONDecodeError as e:
        return [{
            "line": getattr(e, 'lineno', 1),
            "issue": f"❌ JSON syntax error: {str(e)}",
            "fix": "Fix the JSON syntax error"
        }]
    
    # Validate file naming
    issues.extend(check_file_naming(filename))
    
    # Validate JSON structure
    issues.extend(validate_json_structure(data, filename))
    
    # Check for forbidden domains in content
    lines = file_contents.split("\n")
    for i, line in enumerate(lines, start=1):
        for domain in FORBIDDEN_DOMAINS:
            if domain in line:
                issues.append({
                    "line": i,
                    "issue": f"❌ Forbidden domain '{domain}' found",
                    "fix": f"Replace '{domain}' with an allowed domain: {', '.join(ALLOWED_DOMAINS)}"
                })
    
    return issues

def ai_review_pr(pr_body, changed_files, all_file_contents):
    """Enhanced AI review with domain-specific knowledge."""
    
    # Prepare comprehensive context for AI
    files_summary = []
    for filename, content in all_file_contents.items():
        try:
            data = json.loads(content)
            files_summary.append(f"File: {filename}")
            files_summary.append(f"  Domain: {data.get('domain', 'N/A')}")
            files_summary.append(f"  Subdomain: {data.get('subdomain', 'N/A')}")
            files_summary.append(f"  Owner: {data.get('owner', {}).get('username', 'N/A')}")
            files_summary.append(f"  Records: {list(data.get('records', {}).keys())}")
            files_summary.append("")
        except:
            files_summary.append(f"File: {filename} (JSON parse error)")
    
    review_prompt = f"""
You are an expert code reviewer for a FREE SUBDOMAIN REGISTRATION service.

**SERVICE CONTEXT:**
This is is-cool.me - a free subdomain service providing subdomains under:
- is-epic.me (personal sites, projects)
- is-awsm.tech (technical projects)

**MIGRATION NOTICE:** 
- is-cool.me → is-epic.me (FORBIDDEN)
- is-app.tech → is-awsm.tech (FORBIDDEN)

**REVIEW RULES:**
{DOMAIN_RULES}

**PR DETAILS:**
Description: {pr_body or "No description provided"}

**FILES BEING REGISTERED:**
{chr(10).join(files_summary)}

**REVIEW INSTRUCTIONS:**
1. Check if this is a legitimate subdomain registration
2. Verify all technical requirements are met
3. Look for potential abuse or policy violations
4. Ensure proper documentation and contact info
5. Check for suspicious patterns or bulk registrations

**DECISION CRITERIA:**
- ✅ APPROVE: If all rules are followed and registration seems legitimate
- ❌ REQUEST CHANGES: If any violations or issues are found

**OUTPUT FORMAT:**
Start with either "✅ APPROVED" or "❌ REQUEST CHANGES"
Then provide detailed reasoning and specific issues found.

Be thorough but constructive in your feedback.
"""

    try:
        response = g4f.ChatCompletion.create(
            model=g4f.models.gpt_4,
            messages=[{"role": "user", "content": review_prompt}]
        )

        decision = response.get("content", "").strip() if isinstance(response, dict) else response.strip()

        if not decision:
            return "request changes", ["AI review failed. Manual review required."]

        # Parse AI decision
        if "✅ APPROVED" in decision or "approved" in decision.lower():
            return "approve", []
        else:
            # Extract feedback lines
            feedback_lines = [line.strip() for line in decision.split('\n') if line.strip()]
            return "request changes", feedback_lines

    except Exception as e:
        return "request changes", [f"AI review failed: {str(e)}. Manual review required."]

def post_line_comment(pr, filename, line, issue, fix):
    """Posts a comment on a specific line in a PR."""
    body = f"**Issue:** {issue}\n**Suggested Fix:** {fix}"
    try:
        commit = pr.head.repo.get_commit(pr.head.sha)
        pr.create_review_comment(body, commit, filename, line)
    except Exception as e:
        print(f"Failed to post line comment: {e}")
        # Fallback: post as a general PR comment
        pr.create_issue_comment(f"**File:** {filename} (Line {line})\n{body}")

def request_changes(pr, all_issues, ai_feedback):
    """Requests changes on the PR with comprehensive feedback."""
    
    # Group issues by file
    issues_by_file = {}
    for issue in all_issues:
        filename = issue.get("filename", "unknown")
        if filename not in issues_by_file:
            issues_by_file[filename] = []
        issues_by_file[filename].append(issue)
    
    # Post line comments for each file
    for filename, issues in issues_by_file.items():
        for issue in issues:
            post_line_comment(pr, filename, issue["line"], issue["issue"], issue["fix"])
    
    # Create comprehensive review
    review_body = "## 🔍 Domain Registration Review\n\n"
    review_body += "❌ **Changes Required** - Please address the following issues:\n\n"
    
    if all_issues:
        review_body += "### 📋 Technical Issues Found:\n"
        for i, issue in enumerate(all_issues[:10], 1):  # Limit to 10 issues
            review_body += f"{i}. {issue['issue']}\n"
        
        if len(all_issues) > 10:
            review_body += f"\n... and {len(all_issues) - 10} more issues. See individual file comments.\n"
    
    if ai_feedback and isinstance(ai_feedback, list):
        review_body += "\n### 🤖 AI Review Feedback:\n"
        for feedback in ai_feedback[:5]:  # Limit AI feedback
            if feedback.strip():
                review_body += f"- {feedback}\n"
    
    review_body += "\n### 📚 Resources:\n"
    review_body += "- [Registration Guide](https://github.com/is-cool-me/register#register)\n"
    review_body += "- [Domain Rules](https://github.com/is-cool-me/register#domains)\n"
    review_body += "- [Example Files](https://github.com/is-cool-me/register/tree/main/domains)\n"
    
    pr.create_review(event="REQUEST_CHANGES", body=review_body)

def approve_pr(pr):
    """Approves the PR with a welcoming message."""
    try:
        bot_github = Github(BOT_GITHUB_TOKEN)
        bot_repo = bot_github.get_repo(GITHUB_REPOSITORY)
        bot_pr = bot_repo.get_pull(int(PR_NUMBER))

        approval_body = """## ✅ Domain Registration Approved!

🎉 **Welcome to is-cool.me!** Your subdomain registration looks great.

### What happens next:
1. Your PR will be merged automatically
2. DNS changes will propagate within 5-15 minutes
3. Your subdomain will be live within 24 hours

### Need help?
- Join our [Discord server](https://discord.gg/N8YzrkJxYy)
- Check our [documentation](https://github.com/is-cool-me/register)

Thanks for using our free subdomain service! 🚀"""

        bot_pr.create_review(event="APPROVE", body=approval_body)
    except Exception as e:
        print(f"Failed to approve PR: {e}")

def main():
    try:
        github = Github(GITHUB_TOKEN)
        repo = github.get_repo(GITHUB_REPOSITORY)
        pr = fetch_pr(repo)

        changed_files = fetch_changed_files(pr)
        all_issues = []
        all_file_contents = {}

        # Analyze each changed file
        for file in changed_files:
            if not file.startswith("domains/") or not file.endswith(".json"):
                continue  # Skip non-domain files
                
            file_contents = fetch_file_content(repo, file, pr)
            all_file_contents[file] = file_contents
            
            # Analyze file for issues
            issues = analyze_file_contents(file_contents, file)
            for issue in issues:
                issue["filename"] = file  # Add filename to issue
            all_issues.extend(issues)

        # Skip AI review if no domain files changed
        if not all_file_contents:
            print("No domain files changed, skipping review")
            return

        # Get AI review
        ai_decision, ai_feedback = ai_review_pr(pr.body or "", changed_files, all_file_contents)

        # Make decision
        if all_issues or ai_decision == "request changes":
            request_changes(pr, all_issues, ai_feedback)
        else:
            approve_pr(pr)

    except Exception as e:
        print(f"Script failed with error: {e}")
        # Post error comment to PR for debugging
        try:
            github = Github(GITHUB_TOKEN)
            repo = github.get_repo(GITHUB_REPOSITORY)
            pr = fetch_pr(repo)
            pr.create_issue_comment(f"🚨 **AI Review Error:** {str(e)}\n\nManual review required.")
        except:
            pass
        sys.exit(1)

if __name__ == "__main__":
    main()