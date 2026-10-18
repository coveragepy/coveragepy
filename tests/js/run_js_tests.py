# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Run the JavaScript tests in tests/js in a headless browser."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

JS_DIR = Path(__file__).parent


def main() -> int:
    """Run the tests, print the results, and return an exit status."""
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page()
        page.on("pageerror", lambda exc: print(f"Page error: {exc}"))
        page.add_init_script(path=JS_DIR / "collect_results.js")
        page.goto((JS_DIR / "index.html").resolve().as_uri())
        page.wait_for_function("window.qunit_results !== undefined", timeout=30_000)
        results = page.evaluate("window.qunit_results")
        failures = page.evaluate("window.qunit_failures")
        browser.close()

    for failure in failures:
        print(f"FAILED: {' > '.join(failure['name'])}")
        for error in failure["errors"]:
            message = error.get("message") or "Assertion failed"
            actual = json.dumps(error.get("actual"))
            expected = json.dumps(error.get("expected"))
            print(f"    {message}: actual {actual}, expected {expected}")

    counts = results["testCounts"]
    print(
        f"{counts['total']} JavaScript tests: {counts['passed']} passed, "
        + f"{counts['failed']} failed, {counts['skipped']} skipped, {counts['todo']} todo"
    )
    return int(results["status"] != "passed")


if __name__ == "__main__":
    sys.exit(main())
