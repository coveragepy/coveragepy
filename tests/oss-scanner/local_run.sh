# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

# Build the OSS Scanner image from the last commit, then run the tests in it
# with no network, as the scanner will.
#
# This is meant to be sourced, so it avoids `set -e` and `exit`.
# git archive packs only committed files, like the scanner's clean checkout.
# In a subdirectory it would pack only that subdirectory, so use the top.

# Uncommitted changes wouldn't be tested, which is easy to forget.
if [ -n "$(git status --porcelain)" ]; then
    echo "Commit these changes first, they won't be in the image:"
    git status --short
else
    git -C "$(git rev-parse --show-toplevel)" archive HEAD \
        | DOCKER_CLI_HINTS=false docker build -f tests/oss-scanner/Dockerfile -t coveragepy-oss-scanner - \
        && docker run --rm --network none coveragepy-oss-scanner tox -e py313
fi
