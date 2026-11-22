# Build image for the OSS Scanner: https://github.com/anthropics/oss-scanner
# The scanner builds this with the repository as the build context.  Network
# access is only available while building this image, so everything needed to
# build and test coverage.py has to be installed here.

# PYVERSIONS: This runs on 3.13. Update throughout this file as needed.

FROM python:3.13-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONWARNDEFAULTENCODING=1 \
    PYTHON_COLORS=0

# The scanner runs the image with no network.
ENV COVERAGE_TEST_NO_NETWORK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential gdb git \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

RUN python -m pip install -r requirements/tox.txt

# Debug info and frame pointers make C tracer crashes easier to diagnose.
ENV CFLAGS="-g -O1 -fno-omit-frame-pointer"

# Without build isolation, tox can run again later with no network.
ENV COVERAGE_PIP_ARGS=--no-build-isolation

# Run the full test suite as tox.ini defines it, but don't fail the build on
# test failures.
RUN (tox -e py313 || echo "WARNING: tests reported failures")

# tox removes the C extension to test the other cores, so build it again.
RUN .tox/py313/bin/python setup.py --quiet build_ext --inplace \
    && .tox/py313/bin/python -c "import coverage.tracer"

ENV PATH="/src/.tox/py313/bin:$PATH"
