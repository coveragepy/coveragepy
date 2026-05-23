#!/bin/bash
# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

# A suggestion about how to get less hyperfine output:
#   https://github.com/sharkdp/hyperfine/issues/223
HYPERFINE='hyperfine -w 1 -s basic -r 10'

cat > sourcefile1.py << EOF
import random

def get_random_number():
	return random.randint(5, 20)
EOF

cat > test_file1.py << EOF
import pytest
import sourcefile1

tests = tuple(f'test{i}' for i in range(1000))

@pytest.mark.parametrize("input_str", tests)
def test_speed(input_str):
    print(input_str)
    number = sourcefile1.get_random_number()
    assert number <= 20
    assert number >= 5
EOF

rm -f .coveragerc

$HYPERFINE 'python -m pytest test_file1.py'

echo "Coverage 4.5.4"
pip install -q coverage==4.5.4
$HYPERFINE 'python -m coverage run -m pytest test_file1.py'
$HYPERFINE 'python -m coverage run --branch -m pytest test_file1.py'
$HYPERFINE 'python -m pytest --cov=. --cov-report= test_file1.py'
$HYPERFINE 'python -m pytest --cov=. --cov-report= --cov-branch test_file1.py'

echo "Coverage 5.0a8, no contexts"
pip install -q coverage==5.0a8
$HYPERFINE 'python -m coverage run -m pytest test_file1.py'
$HYPERFINE 'python -m coverage run --branch -m pytest test_file1.py'
$HYPERFINE 'python -m pytest --cov=. --cov-report= test_file1.py'
$HYPERFINE 'python -m pytest --cov=. --cov-report= --cov-branch test_file1.py'

echo "Coverage 5.0a8, with test contexts"
cat > .coveragerc <<EOF
[run]
dynamic_context = test_function
EOF

$HYPERFINE 'python -m coverage run -m pytest test_file1.py'
$HYPERFINE 'python -m coverage run --branch -m pytest test_file1.py'
$HYPERFINE 'python -m pytest --cov=. --cov-report= test_file1.py'
$HYPERFINE 'python -m pytest --cov=. --cov-report= --cov-branch test_file1.py'

echo "Pytest-cov contexts"
rm -f .coveragerc

$HYPERFINE 'python -m pytest --cov=. --cov-report= --cov-context=test test_file1.py'
$HYPERFINE 'python -m pytest --cov=. --cov-report= --cov-branch --cov-context=test test_file1.py'
