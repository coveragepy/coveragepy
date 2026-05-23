# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Trigger a repository_dispatch GitHub action."""

import sys
import time

from session import get_session

# The GitHub URL makes no mention of which workflow to use. It's found based on
# the event_type, which matches the types in the workflow:
#
#   on:
#     repository_dispatch:
#       types:
#         - build-kits
#


def latest_action_run(repo_owner, event):
    """
    Get the newest action run for a certain kind of event.
    """
    resp = get_session().get(
        f"https://api.github.com/repos/{repo_owner}/actions/runs?event={event}"
    )
    resp.raise_for_status()
    return resp.json()["workflow_runs"][0]


def dispatch_action(repo_owner, event_type):
    """
    Trigger an action with a particular dispatch event_type.
    Wait until it starts, and print the URL to it.
    """
    latest_id = latest_action_run(repo_owner, "repository_dispatch")["id"]

    url = f"https://api.github.com/repos/{repo_owner}/dispatches"
    data = {"event_type": event_type}

    resp = get_session().post(url, json=data)
    resp.raise_for_status()
    print(f"Success: {resp.status_code}")
    while True:
        run = latest_action_run(repo_owner, "repository_dispatch")
        if run["id"] != latest_id:
            break
        print(".", end=" ", flush=True)
        time.sleep(0.5)
    print(run["html_url"])


if __name__ == "__main__":
    dispatch_action(*sys.argv[1:])
