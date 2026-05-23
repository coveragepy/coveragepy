# Turn a tree of Python files into a series of make_file calls.
for f in **/*.py; do
    echo 'make_file("'$1$f'", """\\'
    sed -e 's/^/    /' <$f
    echo '    """)'
done
