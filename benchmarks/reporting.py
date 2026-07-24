"""Benchmarks for analysis and reporting costs."""

from __future__ import annotations

import io

from coverage import Coverage

from benchmarks.helpers import (
    PACKAGE_NAME,
    REPORT_ROUNDS,
    collect_context_data,
    collect_data,
    fresh_html_dir,
    make_coverage,
    make_workspace,
)


class _ReportingBase:
    """Build measured data once per benchmark sample."""

    def setup(self) -> None:
        self.workspace = make_workspace()
        self.source_files = sorted((self.workspace / PACKAGE_NAME).glob("*.py"))
        self.data_suffix = "pytrace-branch"
        measured = collect_data(self.workspace, core="pytrace", branch=True, rounds=REPORT_ROUNDS)
        measured.save()
        self.cov = make_coverage(
            self.workspace,
            core="pytrace",
            branch=True,
            data_suffix=self.data_suffix,
            source=[],
        )
        self.cov.load()

    def teardown(self) -> None:
        import shutil

        shutil.rmtree(self.workspace, ignore_errors=True)


class TimeAnalysis(_ReportingBase):
    """Measure static-analysis work across all files."""

    def time_analysis2_all_files(self) -> None:
        self.cov._clear_analysis_caches()
        for filename in self.source_files:
            self.cov.analysis2(str(filename))


class TimeReport(_ReportingBase):
    """Measure text and HTML report generation."""

    def time_report_text(self) -> None:
        self.cov._clear_analysis_caches()
        self.cov.report(file=io.StringIO())

    def time_html_report(self) -> None:
        self.cov._clear_analysis_caches()
        html_dir = fresh_html_dir(self.workspace)
        self.cov.html_report(directory=str(html_dir))

    def time_xml_report(self) -> None:
        self.cov._clear_analysis_caches()
        self.cov.xml_report(outfile=str(self.workspace / "coverage.xml"))

    def time_json_report(self) -> None:
        self.cov._clear_analysis_caches()
        self.cov.json_report(outfile=str(self.workspace / "coverage.json"))

    def time_lcov_report(self) -> None:
        self.cov._clear_analysis_caches()
        self.cov.lcov_report(outfile=str(self.workspace / "coverage.lcov"))


class TimeReportReuse(_ReportingBase):
    """Measure repeated reporting on the same loaded data."""

    def time_report_then_html_same_process(self) -> None:
        self.cov._clear_analysis_caches()
        self.cov.report(file=io.StringIO())
        html_dir = fresh_html_dir(self.workspace)
        self.cov.html_report(directory=str(html_dir))


class TimeHtmlContexts(_ReportingBase):
    """Measure HTML generation when context data must be rendered."""

    def setup(self) -> None:
        self.workspace = make_workspace()
        self.source_files = sorted((self.workspace / PACKAGE_NAME).glob("*.py"))
        measured = collect_context_data(self.workspace)
        measured.save()

        self.cov = Coverage(
            data_file=str(self.workspace / ".coverage.contexts"),
            config_file=False,
            source=[],
            branch=True,
        )
        self.cov.set_option("html:show_contexts", True)
        self.cov.load()

    def time_html_report_with_contexts(self) -> None:
        self.cov._clear_analysis_caches()
        html_dir = fresh_html_dir(self.workspace)
        self.cov.html_report(directory=str(html_dir), show_contexts=True)

    def time_html_report_with_filtered_contexts(self) -> None:
        self.cov.set_option("report:contexts", ["test_context_alpha"])
        self.cov._clear_analysis_caches()
        html_dir = fresh_html_dir(self.workspace)
        self.cov.html_report(directory=str(html_dir), show_contexts=True)


class TimeLargeHtml:
    """Measure HTML reporting for large files with many regions."""

    def setup(self) -> None:
        self.workspace = make_workspace(large_module=True)
        measured = collect_data(
            self.workspace, core="pytrace", branch=True, rounds=REPORT_ROUNDS, loops=40
        )
        measured.save()
        self.cov = make_coverage(
            self.workspace,
            core="pytrace",
            branch=True,
            data_suffix="pytrace-branch",
            source=[],
        )
        self.cov.load()

    def teardown(self) -> None:
        import shutil

        shutil.rmtree(self.workspace, ignore_errors=True)

    def time_html_report_large_module(self) -> None:
        self.cov._clear_analysis_caches()
        html_dir = fresh_html_dir(self.workspace)
        self.cov.html_report(directory=str(html_dir))


class TimeHtmlIncremental(_ReportingBase):
    """Measure incremental HTML regeneration against an existing htmlcov dir."""

    def setup(self) -> None:
        super().setup()
        self.html_dir = fresh_html_dir(self.workspace)
        self.cov.html_report(directory=str(self.html_dir))
        self.changed_file = self.source_files[0]
        self.original_source = self.changed_file.read_text(encoding="utf-8")
        self.changed_source = self.original_source + "\n# incremental benchmark change\n"
        self._use_changed_source = False

    def time_html_report_unchanged(self) -> None:
        self.cov._clear_analysis_caches()
        self.cov.html_report(directory=str(self.html_dir))

    def time_html_report_single_source_change(self) -> None:
        self._use_changed_source = not self._use_changed_source
        new_source = self.changed_source if self._use_changed_source else self.original_source
        self.changed_file.write_text(new_source, encoding="utf-8")
        self.cov._clear_analysis_caches()
        self.cov.html_report(directory=str(self.html_dir))
