import sys
import os
import json
import requests
from pathlib import Path
from github import Github
from groq import Groq
import re

sys.path.append(str(Path(__file__).parent.parent.parent))

# GitHub API credentials
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
BOT_GITHUB_TOKEN = os.getenv("BOT")  # Used for approvals
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")
PR_NUMBER = os.getenv("PR_NUMBER")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Domain configuration
ALLOWED_DOMAINS = {"is-epic.me", "is-into.tech"}
FORBIDDEN_DOMAINS = {"is-cool.me", "is-app.tech"}
RESERVED_SUBDOMAINS = {"www", "api", "mail", "ftp", "admin", "root", "test", "staging", "dev", "ns", "ns1", "ns2"}
FORBIDDEN_DNS_PROVIDERS = {
    "ns1.vercel-dns.com", "ns2.vercel-dns.com",
    "dns1.p01.nsone.net", "dns2.p01.nsone.net",
    "dns1.registrar-servers.com", "dns2.registrar-servers.com"
}

# Cloudflare NS patterns (forbidden)
CLOUDFLARE_NS_PATTERNS = [
    r".*\.ns\.cloudflare\.com",
    r"ns[0-9]+\.cloudflare\.com",
    r".*\.cloudflare\.com"
]

# Comprehensive PR Review Guidelines
DOMAIN_RULES = """
### Domain Registration Review Guidelines:

**🎯 ALLOWED DOMAINS:**
- ✅ `is-epic.me` and `is-into.tech` ONLY
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

**🔧 DNS RESTRICTIONS:**
- ❌ Cloudflare NS records (*.ns.cloudflare.com, ns*.cloudflare.com)
- ❌ Netlify hosting (*.netlify.app)
- ❌ Vercel hosting (*.vercel.app)
- ✅ NS records allowed BUT require detailed justification
- ✅ GitHub Pages, custom servers, other providers OK

**📝 NS RECORD REQUIREMENTS:**
- Must include clear description of why NS records are needed
- Must explain what services will be hosted
- Must provide technical justification
- Cannot be used for simple website hosting

**🚫 FORBIDDEN CONTENT:**
- Illegal activities, hate speech, malware
- Copyright infringement, spam, phishing
- Adult content without proper age verification
- Cryptocurrency mining, illegal gambling

**📝 NAMING RULES:**
- Subdomain must be 3-63 characters
- Only lowercase letters, numbers, hyphens
- Cannot start/end with hyphen
- No reserved names (www, api, mail, etc.)

**⚠️ CRITICAL: AUTO-MERGE WARNING**
- Approved PRs merge automatically
- Be extremely careful with approvals
- When in doubt, request changes
- Manual review preferred for complex cases
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

def check_cloudflare_ns(ns_record):
    """Check if NS record is from Cloudflare (forbidden)."""
    for pattern in CLOUDFLARE_NS_PATTERNS:
        if re.match(pattern, ns_record, re.IGNORECASE):
            return True
    return False

def validate_ns_records_justification(data, pr_body):
    """Validates NS records have proper justification."""
    issues = []
    
    if "records" in data and "NS" in data["records"]:
        ns_records = data["records"]["NS"]
        
        # Check for Cloudflare NS (forbidden)
        for ns in ns_records:
            if check_cloudflare_ns(ns):
                issues.append({
                    "line": 1,
                    "issue": f"❌ Cloudflare NS record forbidden: '{ns}'",
                    "fix": "Use non-Cloudflare nameservers. Cloudflare NS records are not allowed."
                })
        
        # Check for justification in PR description
        if not pr_body or len(pr_body.strip()) < 50:
            issues.append({
                "line": 1,
                "issue": "❌ NS records require detailed justification in PR description",
                "fix": "Add detailed explanation of why NS records are needed, what services will be hosted, and technical justification (minimum 50 characters)"
            })
        else:
            # Look for key justification terms
            justification_keywords = [
                "subdomain", "service", "hosting", "server", "application", 
                "website", "api", "database", "email", "dns", "nameserver",
                "technical", "infrastructure", "project", "development"
            ]
            
            pr_lower = pr_body.lower()
            found_keywords = [kw for kw in justification_keywords if kw in pr_lower]
            
            if len(found_keywords) < 2:
                issues.append({
                    "line": 1,
                    "issue": "❌ NS records justification lacks technical details",
                    "fix": "Provide more detailed technical explanation of why NS records are needed. Explain the specific services and infrastructure requirements."
                })
    
    return issues

def validate_json_structure(data, filename, pr_body):
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
                            "fix": "Use allowed DNS providers (not Vercel DNS, etc.)"
                        })
                
                # Validate NS records justification
                issues.extend(validate_ns_records_justification(data, pr_body))
            
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
                    else:
                        # Check for private/reserved IPs
                        octets = [int(x) for x in ip.split('.')]
                        if (octets[0] == 10 or 
                            (octets[0] == 172 and 16 <= octets[1] <= 31) or
                            (octets[0] == 192 and octets[1] == 168) or
                            octets[0] == 127):
                            issues.append({
                                "line": 1,
                                "issue": f"❌ Private/reserved IP address: '{ip}'",
                                "fix": "Use public IP addresses only"
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

def analyze_file_contents(file_contents, filename, pr_body):
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
    
    # Validate JSON structure (pass PR body for NS validation)
    issues.extend(validate_json_structure(data, filename, pr_body))
    
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

def read_readme():
    """Read the README.md file for review guidelines."""
    try:
        readme_path = Path(__file__).parent.parent.parent / "README.md"
        with open(readme_path, 'r') as f:
            return f.read()
    except Exception as e:
        print(f"Warning: Could not read README.md: {e}")
        return ""

def ai_review_pr(pr_body, changed_files, all_file_contents):
    """Enhanced AI review with domain-specific knowledge and auto-merge awareness."""
    
    # Read README for guidelines
    readme_content = read_readme()
    
    # Prepare comprehensive context for AI
    files_summary = []
    has_ns_records = False
    
    for filename, content in all_file_contents.items():
        try:
            data = json.loads(content)
            files_summary.append(f"File: {filename}")
            files_summary.append(f"  Domain: {data.get('domain', 'N/A')}")
            files_summary.append(f"  Subdomain: {data.get('subdomain', 'N/A')}")
            files_summary.append(f"  Owner: {data.get('owner', {}).get('username', 'N/A')}")
            
            records = data.get('records', {})
            files_summary.append(f"  Records: {list(records.keys())}")
            
            if 'NS' in records:
                has_ns_records = True
                files_summary.append(f"  ⚠️  NS Records: {records['NS']}")
            
            files_summary.append("")
        except:
            files_summary.append(f"File: {filename} (JSON parse error)")
    
    review_prompt = f"""
You are an expert code reviewer for a FREE SUBDOMAIN REGISTRATION service.
You MUST review PRs strictly according to the README.md guidelines provided below.

🚨 **CRITICAL: AUTO-MERGE WARNING** 🚨
- If you APPROVE this PR, it will AUTOMATICALLY MERGE
- Be EXTREMELY careful with approvals
- When in doubt, REQUEST CHANGES
- Only approve if you are 100% confident

**README GUIDELINES (MUST FOLLOW):**
{readme_content}

**EXTRACTED KEY RULES FROM README:**
{DOMAIN_RULES}

**PR DETAILS:**
Description: {pr_body or "No description provided"}

**FILES BEING REGISTERED:**
{chr(10).join(files_summary)}

**SPECIAL ATTENTION REQUIRED:**
{"⚠️ NS RECORDS DETECTED - Requires detailed justification!" if has_ns_records else "✅ Standard DNS records"}

**REVIEW CHECKLIST (Based on README):**
1. ✅ Are domains allowed (is-epic.me, is-into.tech only)?
2. ✅ Is JSON structure complete and valid as per README example?
3. ✅ Are DNS records properly formatted (A, AAAA, CNAME, MX, TXT, CAA, SRV, PTR)?
4. ✅ Is owner information complete (username and valid email)?
5. ✅ No forbidden providers (Cloudflare NS, Netlify, Vercel)?
6. ✅ If NS records: Is justification VERY CLEAR and DETAILED as required by README?
7. ✅ No illegal activities, hate speech, malware, or suspicious content?
8. ✅ Follows naming conventions (3-63 chars, lowercase, no reserved names)?
9. ✅ File naming: subdomain.domain.json format in /domains folder?
10. ✅ Clear description provided (required per README line 138)?

**IMPORTANT README REQUIREMENTS:**
- "Wildcard domains and NS records are supported too, but the reason for their registration should be VERY CLEAR and described in DETAIL" (Line 32)
- "Domains used for illegal purposes will be removed and permanently banned. Please provide a CLEAR DESCRIPTION" (Line 138)
- "Don't ignore the pull request checklist" (Line 134)

**DECISION CRITERIA:**
- ✅ APPROVE: ONLY if ALL README requirements are met and registration is clearly legitimate
- ❌ REQUEST CHANGES: If ANY issues, concerns, or missing information per README

**OUTPUT FORMAT:**
Start with either "✅ APPROVED" or "❌ REQUEST CHANGES"
Then provide detailed reasoning based on README guidelines.

Remember: Approved PRs merge automatically. Follow README strictly. Be conservative!
"""

    try:
        # Initialize Groq client
        client = Groq(api_key=GROQ_API_KEY)
        
        # Create chat completion using Groq
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": review_prompt,
                }
            ],
            model="llama-3.3-70b-versatile",  # Using Groq's llama-3.3 70B model for comprehensive reviews
            temperature=0.3,  # Lower temperature for more consistent reviews
            max_tokens=2048,
        )

        decision = chat_completion.choices[0].message.content.strip()

        if not decision:
            return "request changes", ["AI review failed. Manual review required."]

        # Be more conservative with approvals
        if "✅ APPROVED" in decision and "no issues" in decision.lower():
            # Double-check for NS records without proper justification
            if has_ns_records and (not pr_body or len(pr_body.strip()) < 50):
                return "request changes", ["NS records require detailed justification in PR description"]
            return "approve", []
        else:
            # Extract feedback lines
            feedback_lines = [line.strip() for line in decision.split('\n') if line.strip()]
            return "request changes", feedback_lines

    except Exception as e:
        # Always request changes if AI fails
        return "request changes", [f"AI review failed: {str(e)}. Manual review required for safety."]

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
    
    review_body += "\n### ⚠️ Important Notes:\n"
    review_body += "- NS records require detailed technical justification\n"
    review_body += "- Cloudflare NS records are forbidden\n"
    review_body += "- Only use allowed domains: is-epic.me, is-into.tech\n"
    
    review_body += "\n### 📚 Resources:\n"
    review_body += "- [Registration Guide](https://github.com/is-cool-me/register#register)\n"
    review_body += "- [Domain Rules](https://github.com/is-cool-me/register#domains)\n"
    review_body += "- [Example Files](https://github.com/is-cool-me/register/tree/main/domains)\n"
    review_body += "- [Discord Support](https://discord.gg/N8YzrkJxYy)\n"
    
    pr.create_review(event="REQUEST_CHANGES", body=review_body)

def approve_pr(pr):
    """Approves the PR with a welcoming message using bot token for approval."""
    try:
        # Use bot token for approval (has necessary permissions)
        bot_github = Github(BOT_GITHUB_TOKEN)
        bot_repo = bot_github.get_repo(GITHUB_REPOSITORY)
        bot_pr = bot_repo.get_pull(int(PR_NUMBER))

        approval_body = """## ✅ Domain Registration Approved!

🎉 **Welcome to the free subdomain service!** Your subdomain registration has been approved.

**What's Next?**
- Your subdomain will be active within a few minutes
- DNS propagation may take up to 24-48 hours globally
- Check your domain status: `nslookup <your-subdomain>`

**Need Help?**
- Join our [Discord](https://discord.gg/N8YzrkJxYy) for support
- Check [documentation](https://github.com/is-cool-me/register#register)

Thank you for using our service! 🚀
"""
        
        # Create approval review using bot account
        bot_pr.create_review(event="APPROVE", body=approval_body)
        print(f"✅ PR #{PR_NUMBER} approved successfully!")
        
        # Auto-merge the PR after approval
        try:
            bot_pr.merge(merge_method="squash")
            print(f"✅ PR #{PR_NUMBER} merged successfully using squash merge!")
        except Exception as merge_error:
            print(f"⚠️ Auto-merge (squash) failed: {merge_error}")
            print("PR is approved but requires manual merge or has merge conflicts.")
            
    except Exception as e:
        print(f"❌ Error approving PR: {str(e)}")
        raise

def main():
    """Main execution function for the AI code reviewer."""
    try:
        print("🤖 Starting AI Code Reviewer...")
        print(f"Repository: {GITHUB_REPOSITORY}")
        print(f"PR Number: {PR_NUMBER}")
        
        # Validate environment variables
        if not GITHUB_TOKEN:
            print("❌ Error: GITHUB_TOKEN not set")
            sys.exit(1)
        if not BOT_GITHUB_TOKEN:
            print("❌ Error: BOT token not set")
            sys.exit(1)
        if not GROQ_API_KEY:
            print("❌ Error: GROQ_API_KEY not set")
            sys.exit(1)
        
        # Initialize GitHub client
        g = Github(GITHUB_TOKEN)
        repo = g.get_repo(GITHUB_REPOSITORY)
        pr = fetch_pr(repo)
        
        print(f"Reviewing PR: {pr.title}")
        print(f"Author: {pr.user.login}")
        
        # Fetch changed files
        changed_files = fetch_changed_files(pr)
        print(f"Changed files: {len(changed_files)}")
        
        if not changed_files:
            print("⚠️ No files changed in this PR")
            return
        
        # Analyze all changed files
        all_issues = []
        all_file_contents = {}
        
        for filename in changed_files:
            print(f"Analyzing: {filename}")
            
            # Only analyze domain JSON files
            if not filename.startswith("domains/") or not filename.endswith(".json"):
                print(f"  Skipping non-domain file: {filename}")
                continue
            
            file_contents = fetch_file_content(repo, filename, pr)
            if not file_contents:
                print(f"  ⚠️ Could not fetch content for {filename}")
                continue
            
            all_file_contents[filename] = file_contents
            
            # Analyze file
            issues = analyze_file_contents(file_contents, filename, pr.body)
            for issue in issues:
                issue["filename"] = filename
                all_issues.append(issue)
            
            if issues:
                print(f"  ❌ Found {len(issues)} issue(s)")
            else:
                print(f"  ✅ No issues found")
        
        # Get AI review
        print("\n🤖 Running AI review...")
        ai_decision, ai_feedback = ai_review_pr(pr.body, changed_files, all_file_contents)
        
        print(f"AI Decision: {ai_decision}")
        
        # Make final decision
        if all_issues:
            print(f"\n❌ Found {len(all_issues)} technical issue(s)")
            request_changes(pr, all_issues, ai_feedback)
            print("✅ Review posted - requested changes")
        elif ai_decision == "approve":
            print("\n✅ All checks passed - approving PR")
            approve_pr(pr)
        else:
            print("\n⚠️ AI recommends changes")
            request_changes(pr, all_issues, ai_feedback)
            print("✅ Review posted - requested changes based on AI feedback")
        
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
