# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Help make a requests Session with proper authentication."""

import os
import sys

import requests

_SESSIONS = {}


def get_session(env="GITHUB_TOKEN"):
    """Get a properly authenticated requests Session.

    Get the token from the `env` environment variable.
    """

    session = _SESSIONS.get(env)
    if session is None:
        token = os.environ.get(env)
        if token is None:
            sys.exit(f"!! Must have {env}")

        session = requests.session()
        session.headers["Authorization"] = f"token {token}"
        # requests.get() will always prefer the .netrc file even if a header
        # is already set.  This tells it to ignore the .netrc file.
        session.trust_env = False
        _SESSIONS[env] = session

    return session
