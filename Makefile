# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

# Makefile for utility work on coverage.py.

.DEFAULT_GOAL := help


##@ Utilities

.PHONY: help _clean_platform debug_clean clean_platform clean sterile install

help:					## Show this help.
	@# Adapted from https://www.thapaliya.com/en/writings/well-documented-makefiles/
	@echo Available targets:
	@awk -F ':.*##' '/^[^: ]+:.*##/{printf "  \033[1m%-20s\033[m %s\n",$$1,$$2} /^##@/{printf "\n%s\n",substr($$0,5)}' $(MAKEFILE_LIST)

_clean_platform:
	@rm -f *.so */*.so
	@rm -f *.pyd */*.pyd
	@rm -rf __pycache__ */__pycache__ */*/__pycache__ */*/*/__pycache__ */*/*/*/__pycache__ */*/*/*/*/__pycache__
	@rm -f *.pyc */*.pyc */*/*.pyc */*/*/*.pyc */*/*/*/*.pyc */*/*/*/*/*.pyc
	@rm -f *.pyo */*.pyo */*/*.pyo */*/*/*.pyo */*/*/*/*.pyo */*/*/*/*/*.pyo
	@rm -f .DS_Store */.DS_Store */*/.DS_Store */*/*/.DS_Store */*/*/*/.DS_Store

debug_clean:				## Delete various debugging artifacts.
	@rm -rf /tmp/dis /tmp/foo.out $$COVERAGE_DEBUG_FILE

clean: debug_clean _clean_platform	## Remove artifacts of test execution, installation, etc.
	@echo "Cleaning..."
	@-pip uninstall -yq coverage
	@mkdir -p build	# so the chmod won't fail if build doesn't exist
	@chmod -R 777 build
	@rm -rf build coverage.egg-info dist htmlcov
	@rm -f *.bak */*.bak */*/*.bak */*/*/*.bak */*/*/*/*.bak */*/*/*/*/*.bak
	@rm -f coverage/*,cover
	@rm -f MANIFEST
	@rm -f .coverage .coverage.* .metacov*
	@rm -f coverage.xml coverage.json
	@rm -f .tox/*/lib/*/site-packages/a0_metacov.pth
	@rm -f */.coverage */*/.coverage */*/*/.coverage */*/*/*/.coverage */*/*/*/*/.coverage */*/*/*/*/*/.coverage
	@rm -f tests/covmain.zip tests/zipmods.zip tests/zip1.zip
	@rm -rf doc/_build doc/_spell doc/sample_html_beta
	@rm -rf tmp
	@rm -rf a1_coverage.pth
	@rm -rf .*cache */.*cache */*/.*cache */*/*/.*cache .hypothesis
	@rm -rf tests/actual
	@-make -C tests/gold/html clean

sterile: clean				## Remove all non-controlled content, even if expensive.
	rm -rf .tox
	rm -f cheats.txt

# For installing development tooling, use uv if it's available, otherwise pip.
HAS_UV := $(shell command -v uv 2>/dev/null)
ifdef HAS_UV
	INSTALL := uv pip sync
else
	INSTALL := python -m pip install -r
endif

install:				## Install the developer tools.
	$(INSTALL) requirements/dev.pip


##@ Tests and quality checks

.PHONY: lint mypy precommit quality test

lint:					## Run linters and checkers.
	tox -q -e lint

mypy:					## Run the type checker.
	tox -q -e mypy

precommit:				## Run the pre-commit checks.
	PYTHONWARNDEFAULTENCODING= pre-commit run --all-files

quality: lint mypy precommit		## Run all the quality checks.

test:					## Run the test suite.
	tox -q -m py

##@ Metacov: coverage measurement of coverage.py itself
# See metacov.ini for details.

.PHONY: metacov metahtml

metacov:				## Run meta-coverage, measuring ourself.
	COVERAGE_COVERAGE=yes tox -q $(ARGS)

metahtml:				## Produce meta-coverage HTML reports.
	tox exec -q $(ARGS) -- python3 igor.py combine_html


##@ Requirements management

# When updating requirements, a few rules to follow:
#
# 1) Don't install more than one .pip file at once. Always use pip-compile to
# combine .in files onto a single .pip file that can be installed where needed.
#
# 2) Check manual pins before `make upgrade` to see if they can be removed. Look
# in requirements/pins.pip, and search for "windows" in .in files to find pins
# and extra requirements that have been needed, but might be obsolete.

.PHONY: upgrade upgrade_one _upgrade diff_upgrade

DOCBIN = .tox/doc/bin

# PYVERSION to use for kitting, based on cibuildwheel's requirements.
KITVER = py311
KITBIN = .tox/$(KITVER)/bin

$(KITBIN):
	tox -q -e $(KITVER) --notest

# Limit to packages that were released more than 10 days ago.
# https://blog.yossarian.net/2025/11/21/We-should-all-be-using-dependency-cooldowns
PIP_COMPILE = uv pip compile -q --universal --exclude-newer=$$(date -v-10d +%Y-%m-%d) ${COMPILE_OPTS}
upgrade: 				## Update the *.pip files with the latest packages satisfying *.in files.
	$(MAKE) _upgrade COMPILE_OPTS="--upgrade"

upgrade_one:				## Update the *.pip files for one package. `make upgrade_one package=...`
	@test -n "$(package)" || { echo "\nUsage: make upgrade-one package=...\n"; exit 1; }
	$(MAKE) _upgrade COMPILE_OPTS="--upgrade-package $(package)"

_upgrade: export UV_CUSTOM_COMPILE_COMMAND=make upgrade
_upgrade: $(DOCBIN) $(KITBIN)
	$(PIP_COMPILE) -o requirements/pip.pip requirements/pip.in
	$(PIP_COMPILE) -o requirements/pytest.pip requirements/pytest.in
	$(PIP_COMPILE) -p $(KITBIN)/python3 -o requirements/kit.pip requirements/kit.in
	$(PIP_COMPILE) -o requirements/tox.pip requirements/tox.in
	$(PIP_COMPILE) -o requirements/dev.pip requirements/dev.in
	$(PIP_COMPILE) -o requirements/light-threads.pip requirements/light-threads.in
	$(PIP_COMPILE) -o requirements/mypy.pip requirements/mypy.in
	$(PIP_COMPILE) -p $(DOCBIN)/python3 -o doc/requirements.pip doc/requirements.in
	PYTHONWARNDEFAULTENCODING= pre-commit autoupdate

diff_upgrade:				## Summarize the last `make upgrade`.
	@# The sort flags sort by the package name first, then by the -/+, and
	@# sort by version numbers, so we get a summary with lines like this:
	@#	-bashlex==0.16
	@#	+bashlex==0.17
	@#	-build==0.9.0
	@#	+build==0.10.0
	@git diff -U0 | grep -v '^@' | grep == | sort -k1.2,1.99 -k1.1,1.1r -u -V


##@ Pre-builds for prepping the code

.PHONY: css workflows prebuild

CSS = coverage/htmlfiles/style.css
SCSS = coverage/htmlfiles/style.scss

css: $(CSS)				## Compile .scss into .css.
$(CSS): $(SCSS)
	pysassc --style=compact $(SCSS) $@
	cp $@ tests/gold/html/styled

workflows:				## Run cog on the workflows to keep them up-to-date.
	python -m cogapp -crP .github/workflows/*.yml

prebuild: css workflows cogdoc		## One command for all source prep.


##@ Sample HTML reports

.PHONY: _sample_cog_html sample_html sample_html_beta

_sample_cog_html: clean
	python -m pip install -e .
	cd ~/cog; \
		rm -rf htmlcov; \
		PYTEST_ADDOPTS= coverage run --branch --source=cogapp -m pytest -k CogTestsInMemory; \
		coverage combine; \
		coverage html

sample_html: _sample_cog_html		## Generate sample HTML report.
	rm -f doc/sample_html/*.*
	cp -r ~/cog/htmlcov/ doc/sample_html/
	rm doc/sample_html/.gitignore

sample_html_beta: _sample_cog_html	## Generate sample HTML report for a beta release.
	rm -f doc/sample_html_beta/*.*
	cp -r ~/cog/htmlcov/ doc/sample_html_beta/
	rm doc/sample_html_beta/.gitignore


##@ Kitting: making releases

.PHONY: release_version edit_for_release cheats relbranch relcommit1 relcommit2
.PHONY: kit pypi_upload test_upload kit_local build_kits update_rtd
.PHONY: _check_github_auth download_kits
.PHONY: tag bump_version

REPO_OWNER = coveragepy/coveragepy
RTD_PROJECT = coverage

release_version:			#: Update the version for a release.
	python igor.py release_version

edit_for_release:			#: Edit sources to insert release facts (see howto.txt).
	python igor.py edit_for_release

cheats:					## Create some useful snippets for releasing.
	python igor.py cheats | tee cheats.txt

relbranch:				#: Create the branch for releasing (see howto.txt).
	git switch -c nedbat/release-$$(date +%Y%m%d-%H%M%S)

relcommit1:				#: Commit the first release changes (see howto.txt).
	git commit -am "docs: prep for $$(python setup.py --version)"

relcommit2:				#: Commit the latest sample HTML report (see howto.txt).
	git add doc/sample_html
	git commit -am "docs: sample HTML for $$(python setup.py --version)"

kit:					## Make a source distribution and some wheels.
	@# Makes sdist and binary wheel for current Python version and platform:
	python -m build
	@# Makes py3-none-any wheel:
	COVERAGE_DISABLE_EXTENSION=1 python -m build --wheel

pypi_upload:				## Upload the built distributions to PyPI.
	python ci/trigger_action.py $(REPO_OWNER) publish-pypi
	@echo "Use that^ URL to approve the upload"

test_upload:				## Upload the distributions to PyPI's testing server.
	python ci/trigger_action.py $(REPO_OWNER) publish-testpypi
	@echo "Use that^ URL to approve the upload"

kit_local:
	# pip.conf looks like this:
	#   [global]
	#   find-links = file:///Users/ned/Downloads/local_pypi
	cp -v dist/* `awk -F "//" '/find-links/ {print $$2}' ~/.pip/pip.conf`
	# pip caches wheels of things it has installed. Clean them out so we
	# don't go crazy trying to figure out why our new code isn't installing.
	find ~/Library/Caches/pip/wheels -name 'coverage-*' -delete

_check_github_auth:			#: Check that we have GITHUB_TOKEN for other commands that need it.
	@if [[ -z "$$GITHUB_TOKEN" ]]; then \
		echo 'Missing GITHUB_TOKEN: opvars github'; \
		exit 1; \
	fi

build_kits: _check_github_auth		## Trigger GitHub to build all the distributions.
	python ci/trigger_action.py $(REPO_OWNER) build-kits

download_kits: _check_github_auth	## Download the kits built on GitHub.
	@# This is only if we need to examine them for debugging.
	mkdir -p dist
	gh run download --dir=dist $$(gh run list --workflow=Kits --json=databaseId --jq='.[0].databaseId')

tag:					#: Make a git tag with the version number (see howto.txt).
	git tag -s -m "Version $$(python setup.py --version)" $$(python setup.py --version)
	git push --follow-tags

update_rtd:				#: Update ReadTheDocs with the versions to show.
	python ci/update_rtfd.py $(RTD_PROJECT)

bump_version:				#: Edit sources to bump the version after a release (see howto.txt).
	git switch -c nedbat/bump-version
	python igor.py bump_version
	git commit -a -m "build: bump version to $$(python setup.py --version | sed 's/a.*//')"
	git push -u origin @


##@ Documentation

.PHONY: cogdoc dochtml docdev docspell

SPHINXOPTS = -aE
SPHINXBUILD = $(DOCBIN)/sphinx-build $(SPHINXOPTS)
SPHINXAUTOBUILD = $(DOCBIN)/sphinx-autobuild --port 9876 --ignore '.git/**' --open-browser

$(DOCBIN):
	tox -q -e doc --notest

cogdoc: $(DOCBIN)			## Run docs through cog.
	$(DOCBIN)/python -m cogapp -crP --verbosity=1 doc/*.rst doc/*/*.rst

dochtml: cogdoc $(DOCBIN)		## Build the docs HTML output.
	$(SPHINXBUILD) -b html doc doc/_build/html
	@echo "Start at: doc/_build/html/index.html"

docdev: dochtml				## Build docs, and auto-watch for changes.
	PATH=$(DOCBIN):$(PATH) $(SPHINXAUTOBUILD) -b html doc doc/_build/html

docspell: $(DOCBIN)			## Run the spell checker on the docs.
	# Very mac-specific...
	PYENCHANT_LIBRARY_PATH=/opt/homebrew/lib/libenchant-2.dylib $(SPHINXBUILD) -b spelling doc doc/_spell


##@ Publishing docs

.PHONY: publish publishbeta github_releases comment_on_fixes

WEBHOME = ~/web/stellated
WEBSAMPLE = $(WEBHOME)/files/sample_coverage_html
WEBSAMPLEBETA = $(WEBHOME)/files/sample_coverage_html_beta

publish:				## Publish the sample HTML report.
	rm -f $(WEBSAMPLE)/*.*
	mkdir -p $(WEBSAMPLE)
	cp doc/sample_html/*.* $(WEBSAMPLE)

publishbeta:
	rm -f $(WEBSAMPLEBETA)/*.*
	mkdir -p $(WEBSAMPLEBETA)
	cp doc/sample_html_beta/*.* $(WEBSAMPLEBETA)

CHANGES_MD = tmp/rst_rst/changes.md
SCRIV_SOURCE = tmp/only-changes.md

$(CHANGES_MD): CHANGES.rst $(DOCBIN)
	$(SPHINXBUILD) -b rst doc tmp/rst_rst
	pandoc -frst -tmarkdown_strict --markdown-headings=atx --wrap=none tmp/rst_rst/changes.rst > $(CHANGES_MD)

$(SCRIV_SOURCE): $(CHANGES_MD)
	@# Trim parts of the file that aren't changelog entries.
	sed -n -e '/## Version/,/## Earlier/p' < $(CHANGES_MD) > tmp/trimmed.md
	@# Replace sphinx references with published URLs.
	sed -r -e 's@]\(([a-zA-Z0-9_]+)\.rst#([^)]+)\)@](https://coverage.readthedocs.io/en/latest/\1.html#\2)@g' < tmp/trimmed.md > $(SCRIV_SOURCE)

github_releases: $(SCRIV_SOURCE)	## Update GitHub releases.
	$(DOCBIN)/python -m scriv github-release --all

comment_on_fixes: $(SCRIV_SOURCE)	## Add a comment to issues that were fixed.
	python ci/comment_on_fixes.py $(REPO_OWNER)
