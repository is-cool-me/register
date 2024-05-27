import sys
from pathlib import Path
import os
import re
import json
import requests
from typing import Union, List
from github import Github
from github.PullRequest import PullRequest

# Add the parent directory to the Python path
sys.path.append(str(Path(__file__).parent.parent.parent))

import g4f

# Enable logging for g4f
g4f.debug.logging = True
g4f.debug.version_check = False

# Retrieve environment variables
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
GITHUB_REPOSITORY = os.getenv('GITHUB_REPOSITORY')
G4F_PROVIDER = os.getenv('G4F_PROVIDER')
G4F_MODEL = os.getenv('G4F_MODEL') or g4f.models.gpt_4

def get_pr_details(github: Github) -> Union[PullRequest, None]:
    """Retrieve pull request details."""
    try:
        with open('./pr_number', 'r') as file:
            pr_number = file.read().strip()
        if not pr_number:
            print("PR number not found.")
            return None

        repo = github.get_repo(GITHUB_REPOSITORY)
        pull = repo.get_pull(int(pr_number))
        return pull
    except Exception as e:
        print(f"Error fetching PR details: {e.__class__.__name__}: {e}")
        return None

def get_diff(diff_url: str) -> str:
    """Fetch the diff of the pull request."""
    try:
        response = requests.get(diff_url)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching diff: {e}")
        return ""

def read_json(text: str) -> dict:
    """Parse JSON from a markdown code block."""
    match = re.search(r"```(json|)\n(?P<code>[\S\s]+?)\n```", text)
    if match:
        text = match.group("code")
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        print("Invalid JSON format:", text)
        return {}

def read_text(text: str) -> str:
    """Extract text from a markdown code block."""
    match = re.search(r"```(markdown|)\n(?P<text>[\S\s]+?)\n```", text)
    if match:
        return match.group("text")
    return text

def get_ai_response(prompt: str, as_json: bool = True) -> Union[dict, str]:
    """Get a response from g4f API."""
    try:
        response = g4f.ChatCompletion.create(
            G4F_MODEL,
            [{'role': 'user', 'content': prompt}],
            G4F_PROVIDER,
            ignore_stream_and_auth=True
        )
        return read_json(response) if as_json else read_text(response)
    except Exception as e:
        print(f"Error getting AI response: {e}")
        return {} if as_json else ""

def analyze_code(pull: PullRequest, diff: str) -> List[dict]:
    """Analyze code changes in the pull request."""
    comments = []
    changed_lines = []
    current_file_path = None
    offset_line = 0

    for line in diff.split('\n'):
        if line.startswith('+++ b/'):
            current_file_path = line[6:]
            changed_lines = []
        elif line.startswith('@@'):
            match = re.search(r'\+([0-9]+?),', line)
            if match:
                offset_line = int(match.group(1))
        elif current_file_path:
            if (line.startswith('\\') or line.startswith('diff')) and changed_lines:
                prompt = create_analyze_prompt(changed_lines, pull, current_file_path)
                response = get_ai_response(prompt)
                for review in response.get('reviews', []):
                    review['path'] = current_file_path
                    comments.append(review)
                current_file_path = None
            elif line.startswith('-'):
                changed_lines.append(line)
            else:
                changed_lines.append(f"{offset_line}:{line}")
                offset_line += 1

    return comments

def create_analyze_prompt(changed_lines: List[str], pull: PullRequest, file_path: str) -> str:
    """Create a prompt for analyzing the code changes."""
    code = "\n".join(changed_lines)
    example = '{"reviews": [{"line": <line_number>, "body": "<review comment>"}]}'
    return f"""
    Your task is to review pull requests. Instructions:
    - Provide the response in following JSON format: {example}
    - Do not give positive comments or compliments.
    - Provide comments and suggestions ONLY if there is something to improve, otherwise "reviews" should be an empty array.
    - Write the comment in GitHub Markdown format.
    - Use the given description only for the overall context and only comment the code.
    - IMPORTANT: NEVER suggest adding comments to the code.

    Review the following code diff in the file "{file_path}" and take the pull request title and description into account when writing the response.

    Pull request title: {pull.title}
    Pull request description:
    ---
    {pull.body}
    ---

    Each line is prefixed by its number. Code to review:
    ```
    {code}
    ```
    """

def create_review_prompt(pull: PullRequest, diff: str) -> str:
    """Create a prompt for generating the review comment."""
    return f"""
    Your task is to review a pull request. Instructions:
    - Write in name of is-cool-me copilot. Don't use placeholder.
    - Write the review in GitHub Markdown format.
    - Thank the author for contributing to the project.

    Pull request author: {pull.user.name}
    Pull request title: {pull.title}
    Pull request description:
    ---
    {pull.body}
    ---

    Diff:
    ```diff
    {diff}
    ```
    """

def main():
    """Main function to execute the script."""
    if not all([GITHUB_TOKEN, GITHUB_REPOSITORY, G4F_PROVIDER]):
        print("Environment variables GITHUB_TOKEN, GITHUB_REPOSITORY, or G4F_PROVIDER are not set.")
        exit(1)

    try:
        github = Github(GITHUB_TOKEN)
        pull = get_pr_details(github)
        if not pull:
            exit()
        
        # Option to bypass the existing review check
        bypass_existing_review_check = True  # Set to False if you want to keep the check
        
        if not bypass_existing_review_check:
            if pull.get_reviews().totalCount > 0 or pull.get_issue_comments().totalCount > 0:
                print("Pull request already has a review or comments.")
                exit()

        diff = get_diff(pull.diff_url)
        if not diff:
            exit()
    except Exception as e:
        print(f"Error getting PR details or diff: {e}")
        exit(1)

    try:
        review = get_ai_response(create_review_prompt(pull, diff), False)
    except Exception as e:
        print(f"Error creating review prompt: {e}")
        exit(1)

    try:
        comments = analyze_code(pull, diff)
    except Exception as e:
        print(f"Error analyzing code: {e}")
        exit(1)

    print("Comments:", comments)

    try:
        if comments:
            pull.create_review(body=review, comments=comments)
        else:
            pull.create_issue_comment(body=review)
    except Exception as e:
        print(f"Error posting review or comment: {e}")
        exit(1)

if __name__ == "__main__":
    main()
