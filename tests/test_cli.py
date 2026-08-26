"""End-to-end tests for the command-line interface and output formats."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from phishhawk.cli import EXIT_FLAGGED, EXIT_NO_INPUT, EXIT_OK, main

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")
PHISH = os.path.join(SAMPLES_DIR, "01_credential_phish_m365.eml")
CLEAN = os.path.join(SAMPLES_DIR, "04_legitimate_github.eml")


def run(*argv: str) -> tuple[int, str, str]:
    """Invoke the CLI, capturing exit code, stdout and stderr."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestScan(unittest.TestCase):
    def test_text_report_contains_verdict_and_evidence(self) -> None:
        code, out, _ = run("scan", PHISH, "--no-color")
        self.assertEqual(code, EXIT_FLAGGED)
        self.assertIn("CRITICAL", out)
        self.assertIn("FINDINGS", out)
        self.assertIn("RECOMMENDED ACTIONS", out)
        self.assertIn("SEND004", out)

    def test_clean_message_exits_zero(self) -> None:
        code, out, _ = run("scan", CLEAN, "--no-color")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("BENIGN", out)

    def test_json_output_is_valid(self) -> None:
        _, out, _ = run("scan", PHISH, "-f", "json", "--no-color")
        payload = json.loads(out)
        self.assertEqual(payload["tool"], "phishhawk")
        self.assertEqual(payload["count"], 1)
        result = payload["results"][0]
        self.assertEqual(result["verdict"], "CRITICAL")
        self.assertIn("findings", result)
        self.assertIn("defanged_iocs", result)
        self.assertIn("recommended_actions", result)

    def test_json_iocs_are_defanged(self) -> None:
        _, out, _ = run("scan", PHISH, "-f", "json", "--no-color")
        payload = json.loads(out)
        for url in payload["results"][0]["defanged_iocs"]["urls"]:
            self.assertNotIn("https://", url)

    def test_html_output_is_self_contained(self) -> None:
        _, out, _ = run("scan", PHISH, "-f", "html", "--no-color")
        self.assertTrue(out.lstrip().startswith("<!doctype html>"))
        self.assertIn("</html>", out)
        self.assertIn("<style>", out)
        # No external asset references — the report must open offline.
        for marker in ("src=\"http", "href=\"http://cdn", "<script"):
            self.assertNotIn(marker, out)

    def test_html_escapes_message_content(self) -> None:
        _, out, _ = run("scan", PHISH, "-f", "html", "--no-color")
        self.assertNotIn("<form action=", out)

    def test_markdown_output(self) -> None:
        _, out, _ = run("scan", PHISH, "-f", "markdown", "--no-color")
        self.assertIn("# PhishHawk report", out)
        self.assertIn("## Findings", out)
        self.assertIn("## Recommended actions", out)

    def test_csv_output_has_header_and_row(self) -> None:
        _, out, _ = run("scan", PHISH, "-f", "csv", "--no-color")
        lines = [line for line in out.splitlines() if line.strip()]
        self.assertTrue(lines[0].startswith("file,verdict,score"))
        self.assertEqual(len(lines), 2)

    def test_output_to_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "report.json")
            code, _, err = run("scan", PHISH, "-f", "json", "-o", target)
            self.assertEqual(code, EXIT_FLAGGED)
            self.assertIn("wrote", err)
            with open(target, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["count"], 1)

    def test_verbose_shows_descriptions(self) -> None:
        _, out, _ = run("scan", PHISH, "-v", "--no-color")
        self.assertIn("The sending domain typosquats", out)

    def test_disable_switches_a_rule_off(self) -> None:
        _, with_rule, _ = run("scan", PHISH, "--no-color")
        _, without, _ = run("scan", PHISH, "--no-color", "--disable", "SEND004")
        self.assertIn("SEND004", with_rule)
        self.assertNotIn("SEND004", without)

    def test_missing_file_reports_error(self) -> None:
        code, _, err = run("scan", "/nonexistent/path/message.eml", "--no-color")
        self.assertEqual(code, EXIT_NO_INPUT)
        self.assertIn("no such file", err)

    def test_no_paths_exits_cleanly(self) -> None:
        code, _, _ = run("scan", "--no-color")
        self.assertEqual(code, EXIT_NO_INPUT)


class TestTriage(unittest.TestCase):
    def test_table_lists_all_samples_worst_first(self) -> None:
        code, out, _ = run("triage", SAMPLES_DIR, "--no-color")
        self.assertEqual(code, EXIT_FLAGGED)
        lines = [line for line in out.splitlines() if line.strip()]
        self.assertIn("VERDICT", lines[0])
        self.assertIn("CRITICAL", out)
        self.assertIn("summary", out)
        first_verdict_line = lines[2]
        self.assertIn("CRITICAL", first_verdict_line)

    def test_min_score_filter(self) -> None:
        _, out, _ = run("triage", SAMPLES_DIR, "--no-color", "--min-score", "90")
        self.assertNotIn("BENIGN", out.split("summary")[0])

    def test_verdict_filter(self) -> None:
        _, out, _ = run("triage", SAMPLES_DIR, "--no-color", "--verdict", "HIGH")
        table = out.split("summary")[0]
        self.assertNotIn("04_legitimate_github", table)

    def test_fail_on_threshold_respected(self) -> None:
        code, _, _ = run("triage", CLEAN, "--no-color", "--fail-on", "CRITICAL")
        self.assertEqual(code, EXIT_OK)
        code, _, _ = run("triage", PHISH, "--no-color", "--fail-on", "CRITICAL")
        self.assertEqual(code, EXIT_FLAGGED)

    def test_exit_code_reflects_worst_message_not_filtered_view(self) -> None:
        """Filters change what is displayed, never whether the run failed."""
        code, _, _ = run("triage", SAMPLES_DIR, "--no-color", "--verdict", "CRITICAL")
        self.assertEqual(code, EXIT_FLAGGED)

    def test_html_triage_has_summary_table(self) -> None:
        _, out, _ = run("triage", SAMPLES_DIR, "-f", "html", "--no-color")
        self.assertIn("Triage summary", out)
        self.assertIn("PhishHawk triage report", out)

    def test_csv_triage_lists_every_sample(self) -> None:
        _, out, _ = run("triage", SAMPLES_DIR, "-f", "csv", "--no-color")
        rows = [line for line in out.splitlines() if line.strip()]
        self.assertEqual(len(rows), 7)  # header + 6 samples


class TestIOCs(unittest.TestCase):
    def test_ioc_list_is_defanged_by_default(self) -> None:
        _, out, _ = run("iocs", PHISH, "--no-color")
        self.assertIn("# urls", out)
        self.assertIn("hxxps[://]", out)
        self.assertNotIn("https://", out)

    def test_fanged_flag_emits_live_indicators(self) -> None:
        _, out, _ = run("iocs", PHISH, "--no-color", "--fanged")
        self.assertIn("https://", out)

    def test_sections_present(self) -> None:
        _, out, _ = run("iocs", SAMPLES_DIR, "--no-color")
        for section in ("# urls", "# domains", "# emails", "# sha256"):
            self.assertIn(section, out)


class TestHeaders(unittest.TestCase):
    def test_succeeds_even_on_malicious_mail(self) -> None:
        """`headers` only renders; it must not fail a `set -e` script."""
        code, _, _ = run("headers", PHISH, "--no-color")
        self.assertEqual(code, EXIT_OK)

    def test_chain_and_auth_rendered(self) -> None:
        _, out, _ = run("headers", PHISH, "--no-color")
        self.assertIn("authentication", out)
        self.assertIn("delivery chain", out)
        self.assertIn("SPF", out)
        self.assertIn("mail-delivery-svc.top", out)

    def test_all_flag_dumps_every_header(self) -> None:
        _, out, _ = run("headers", PHISH, "--no-color", "--all")
        self.assertIn("all headers", out)
        self.assertIn("X-Mailer", out)


class TestRules(unittest.TestCase):
    def test_listing_includes_categories_and_count(self) -> None:
        code, out, _ = run("rules", "--no-color")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("AUTHENTICATION", out)
        self.assertIn("AUTH001", out)
        self.assertIn("rules", out)

    def test_json_listing_is_valid(self) -> None:
        _, out, _ = run("rules", "-f", "json", "--no-color")
        rules = json.loads(out)
        self.assertTrue(all({"id", "name", "weight", "category"} <= set(r) for r in rules))

    def test_markdown_listing(self) -> None:
        _, out, _ = run("rules", "-f", "markdown", "--no-color")
        self.assertIn("| ID | Weight |", out)

    def test_category_filter(self) -> None:
        _, out, _ = run("rules", "--category", "attachments", "--no-color")
        self.assertIn("ATT001", out)
        self.assertNotIn("AUTH001", out)


class TestStdinAndDirectories(unittest.TestCase):
    def test_recursive_directory_walk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            nested = os.path.join(tmp, "a", "b")
            os.makedirs(nested)
            with open(PHISH, "rb") as src, open(os.path.join(nested, "m.eml"), "wb") as dst:
                dst.write(src.read())

            _, shallow, _ = run("triage", tmp, "--no-color")
            self.assertNotIn("CRITICAL", shallow)

            _, deep, _ = run("triage", tmp, "-r", "--no-color")
            self.assertIn("CRITICAL", deep)

    def test_empty_file_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            open(os.path.join(tmp, "empty.eml"), "w").close()
            code, _, err = run("triage", tmp, "--no-color")
            self.assertEqual(code, EXIT_NO_INPUT)
            self.assertIn("skipping empty", err)

    def test_mbox_is_unpacked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "archive.mbox")
            with open(PHISH, "rb") as handle:
                body = handle.read()
            with open(path, "wb") as handle:
                for index in range(2):
                    handle.write(f"From sender{index}@example.com Tue Aug 12 03:14:22 2025\n".encode())
                    handle.write(body)
                    handle.write(b"\n")
            _, out, _ = run("triage", path, "--no-color")
            self.assertIn("total=2", out)


class TestTopLevel(unittest.TestCase):
    def test_no_command_prints_help(self) -> None:
        code, out, _ = run()
        self.assertEqual(code, EXIT_OK)
        self.assertIn("usage:", out)

    def test_version_flag(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            run("--version")
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
