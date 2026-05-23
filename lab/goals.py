# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""\
Check coverage goals.

Use `coverage json` to get a coverage.json file, then run this tool
to check goals for subsets of files.

Patterns can use '**/foo*.py' to find files anywhere in the project,
and '!**/something.py' to exclude files matching a pattern.

--file will check each file individually for the required coverage.
--group checks the entire group collectively.

"""

import argparse
import json
import sys

from wcmatch import fnmatch as wcfnmatch  # python -m pip install wcmatch

from coverage.results import Numbers  # Note: an internal class!


def select_files(files, pat):
    flags = wcfnmatch.NEGATE | wcfnmatch.NEGATEALL
    selected = [f for f in files if wcfnmatch.fnmatch(f, pat, flags=flags)]
    return selected


def total_for_files(data, files):
    total = Numbers(precision=3)
    for f in files:
        sel_summ = data["files"][f]["summary"]
        total += Numbers(
            n_statements=sel_summ["num_statements"],
            n_excluded=sel_summ["excluded_lines"],
            n_missing=sel_summ["missing_lines"],
            n_branches=sel_summ.get("num_branches", 0),
            n_partial_branches=sel_summ.get("num_partial_branches", 0),
            n_missing_branches=sel_summ.get("missing_branches", 0),
        )

    return total


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", "-f", action="store_true", help="Check each file individually")
    parser.add_argument("--group", "-g", action="store_true", help="Check a group of files")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Be chatty about what's happening"
    )
    parser.add_argument("goal", type=float, help="Coverage goal")
    parser.add_argument("pattern", type=str, nargs="+", help="Patterns to check")
    args = parser.parse_args(argv)

    print("** Note: this is a proof-of-concept. Support is not promised. **")
    print("Read more: https://nedbatchelder.com/blog/202111/coverage_goals.html")
    print("Feedback is appreciated: https://github.com/coveragepy/coveragepy/issues/691")

    if args.file and args.group:
        print("Can't use --file and --group together")
        return 1
    if not (args.file or args.group):
        print("Need either --file or --group")
        return 1

    with open("coverage.json", encoding="utf-8") as j:
        data = json.load(j)
    all_files = list(data["files"].keys())
    selected = select_files(all_files, args.pattern)

    ok = True
    if args.group:
        total = total_for_files(data, selected)
        pat_nice = ",".join(args.pattern)
        result = f"Coverage for {pat_nice} is {total.pc_covered_str}"
        if total.pc_covered < args.goal:
            print(f"{result}, below {args.goal}")
            ok = False
        elif args.verbose:
            print(result)
    else:
        for fname in selected:
            total = total_for_files(data, [fname])
            result = f"Coverage for {fname} is {total.pc_covered_str}"
            if total.pc_covered < args.goal:
                print(f"{result}, below {args.goal}")
                ok = False
            elif args.verbose:
                print(result)

    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
