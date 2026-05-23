# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

help:
	@echo "Available targets:"
	@grep '^[a-zA-Z]' $(MAKEFILE_LIST) | sort | awk -F ':.*?## ' 'NF==2 {printf "  %-26s%s\n", $$1, $$2}'

complete: 	## Copy support files into directories so the HTML can be viewed properly.
	@for sub in * ../../actual/html/*; do \
		if [ -f "$$sub/index.html" ]; then \
			echo Copying into $$sub ; \
			cp -n support/* $$sub ; \
		fi ; \
	done ; \
	true	# because the for loop exits with 1 for some reason.

clean:		## Remove the effects of this Makefile.
	@git clean -fq .

update-gold:	## Copy actual output files from latest tests to gold files.
	@for sub in ../../actual/html/*; do \
		rsync --verbose --existing --recursive $$sub/ $$(basename $$sub) ; \
	done ; \
	true

update-support:	## Copy latest support files here for posterity.
	python -m pip install -e ../../..
	git rm --ignore-unmatch support/*.{css,js,png}
	mkdir -p support
	python ../../../igor.py copy_with_hash ../../../coverage/htmlfiles/*.{css,js,png} support
	git add support
