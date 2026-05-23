# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""\
Select certain contexts from a coverage.py data file.
"""

import argparse
import re
import sys

import coverage


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--include", type=str, help="Regex for contexts to keep")
    parser.add_argument("--exclude", type=str, help="Regex for contexts to discard")
    args = parser.parse_args(argv)

    print("** Note: this is a proof-of-concept. Support is not promised. **")
    print("Feedback is appreciated: https://github.com/coveragepy/coveragepy/issues/668")

    cov_in = coverage.Coverage()
    cov_in.load()
    data_in = cov_in.get_data()
    print(f"Contexts in {data_in.data_filename()}:")
    for ctx in sorted(data_in.measured_contexts()):
        print(f"    {ctx}")

    if args.include is None and args.exclude is None:
        print("Nothing to do, no output written.")
        return

    out_file = "output.data"
    file_names = data_in.measured_files()
    print(f"{len(file_names)} measured files")
    print(f"Writing to {out_file}")
    cov_out = coverage.Coverage(data_file=out_file)
    data_out = cov_out.get_data()

    for ctx in sorted(data_in.measured_contexts()):
        if args.include is not None:
            if not re.search(args.include, ctx):
                print(f"Skipping context {ctx}, not included")
                continue
        if args.exclude is not None:
            if re.search(args.exclude, ctx):
                print(f"Skipping context {ctx}, excluded")
                continue
        print(f"Keeping context {ctx}")
        data_in.set_query_context(ctx)
        data_out.set_context(ctx)
        if data_in.has_arcs():
            data_out.add_arcs({f: data_in.arcs(f) for f in file_names})
        else:
            data_out.add_lines({f: data_in.lines(f) for f in file_names})

    for fname in file_names:
        data_out.touch_file(fname, data_in.file_tracer(fname))

    cov_out.save()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
