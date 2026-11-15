/* Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0 */
/* For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt */

// Collect QUnit results for tests/js/run_js_tests.py.
/*global QUnit */

// QUnit starts running on the window load event, so we have to subscribe
// before then. By DOMContentLoaded, QUnit has been defined but hasn't started.
document.addEventListener("DOMContentLoaded", () => {
    window.qunit_failures = [];
    QUnit.on("testEnd", test => {
        if (test.status === "failed") {
            // QUnit discards the actual and expected values once the test is
            // over, so copy them now.
            window.qunit_failures.push({
                name: test.fullName,
                errors: test.errors.map(({message, actual, expected}) => ({message, actual, expected})),
            });
        }
    });
    QUnit.on("runEnd", run => {
        window.qunit_results = run;
    });
});
