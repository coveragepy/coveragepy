# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Add a release comment to all the issues mentioned in the latest release."""

import re
import sys

from scriv.scriv import Scriv

from session import get_session

scriv = Scriv()
changelog = scriv.changelog()
changelog.read()

# Get the first entry in the changelog:
for etitle, sections in changelog.entries().items():
    version = etitle.split()[1]  # particular to our title format.
    text = "\n".join(sections)
    break

comment = (
    f"This is now released as part of [coverage {version}]"
    + f"(https://pypi.org/project/coverage/{version})."
)
print(f"Comment will be:\n\n{comment}\n")

repo_owner = sys.argv[1]
url_matches = re.finditer(rf"https://github.com/{repo_owner}/(issues|pull)/(\d+)", text)
urls = {(m[0], m[1], m[2]) for m in url_matches}

for url, kind, number in urls:
    do_comment = False

    if kind == "issues":
        url = f"https://api.github.com/repos/{repo_owner}/issues/{number}"
        issue_data = get_session().get(url).json()
        html_url = issue_data["html_url"]
        if issue_data["state"] == "closed":
            do_comment = True
        else:
            print(f"Still open, comment manually: {url}")
    else:
        url = f"https://api.github.com/repos/{repo_owner}/pulls/{number}"
        pull_data = get_session().get(url).json()
        html_url = pull_data["html_url"]
        if pull_data["state"] == "closed":
            if pull_data["merged"]:
                do_comment = True
            else:
                print(f"Not merged, comment manually: {html_url}")
        else:
            print(f"Still open, comment manually: {html_url}")

    if do_comment:
        print(f"Commenting on {html_url}")
        url = f"https://api.github.com/repos/{repo_owner}/issues/{number}/comments"
        resp = get_session().post(url, json={"body": comment})
        print(resp)
