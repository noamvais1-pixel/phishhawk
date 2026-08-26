"""Tests for the rule engine, scoring, mitigations and verdict bands."""

from __future__ import annotations

import os
import unittest

from phishhawk.analyzer import (
    CATEGORY_CAPS,
    HARD_SIGNALS,
    analyze,
    analyze_bytes,
    worse_of,
)
from phishhawk.parser import parse_bytes
from phishhawk.rules import ALL_RULES, CONTEXT_RULES

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")

BENIGN = b"""From: "Colleague" <colleague@example.com>
To: <me@example.com>
Subject: Notes from today's sync
Date: Mon, 11 Aug 2025 09:31:45 +0000
Message-ID: <note-1@example.com>
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.com;
 dkim=pass header.d=example.com; dmarc=pass header.from=example.com

Hi, here are the notes from our meeting. Nothing urgent, talk tomorrow.
"""


def _rule(rule_id: str):
    for rule in ALL_RULES + CONTEXT_RULES:
        if rule.id == rule_id:
            return rule
    raise AssertionError(f"unknown rule {rule_id}")


def _fired(analysis) -> set[str]:
    return {f.rule_id for f in analysis.findings}


class TestBenignBaseline(unittest.TestCase):
    def test_ordinary_mail_scores_benign(self) -> None:
        analysis = analyze_bytes(BENIGN, source="benign")
        self.assertEqual(analysis.verdict, "BENIGN")
        self.assertLess(analysis.score, 15)

    def test_score_never_negative(self) -> None:
        self.assertGreaterEqual(analyze_bytes(BENIGN).score, 0)


class TestAuthenticationRules(unittest.TestCase):
    def _with_auth(self, auth: str) -> set[str]:
        raw = (
            b"From: a@example.com\nTo: b@example.com\nSubject: t\n"
            + f"Authentication-Results: mx; {auth}\n".encode()
            + b"\nbody\n"
        )
        return _fired(analyze_bytes(raw))

    def test_spf_fail_fires(self) -> None:
        self.assertIn("AUTH001", self._with_auth("spf=fail"))

    def test_dkim_fail_fires(self) -> None:
        self.assertIn("AUTH002", self._with_auth("dkim=fail"))

    def test_dmarc_fail_fires(self) -> None:
        self.assertIn("AUTH003", self._with_auth("dmarc=fail"))

    def test_all_pass_fires_nothing(self) -> None:
        fired = self._with_auth("spf=pass; dkim=pass; dmarc=pass")
        self.assertNotIn("AUTH001", fired)
        self.assertNotIn("AUTH003", fired)

    def test_missing_auth_headers_fire_auth004(self) -> None:
        raw = b"From: a@example.com\nSubject: t\n\nbody\n"
        self.assertIn("AUTH004", _fired(analyze_bytes(raw)))


class TestSenderIdentityRules(unittest.TestCase):
    def test_reply_to_mismatch(self) -> None:
        raw = (b"From: a@example.com\nReply-To: attacker@evil.example\n"
               b"To: b@example.com\nSubject: t\n\nbody\n")
        self.assertIn("SEND001", _fired(analyze_bytes(raw)))

    def test_reply_to_same_domain_does_not_fire(self) -> None:
        raw = (b"From: a@example.com\nReply-To: support@example.com\n"
               b"To: b@example.com\nSubject: t\n\nbody\n")
        self.assertNotIn("SEND001", _fired(analyze_bytes(raw)))

    def test_return_path_mismatch(self) -> None:
        raw = (b"Return-Path: <bounce@other.example>\nFrom: a@example.com\n"
               b"Subject: t\n\nbody\n")
        self.assertIn("SEND002", _fired(analyze_bytes(raw)))

    def test_display_name_brand_spoof(self) -> None:
        raw = (b'From: "PayPal Service" <noreply@random-host.example>\n'
               b"Subject: t\n\nbody\n")
        self.assertIn("SEND003", _fired(analyze_bytes(raw)))

    def test_display_name_matching_domain_does_not_fire(self) -> None:
        raw = b'From: "PayPal" <service@paypal.com>\nSubject: t\n\nbody\n'
        self.assertNotIn("SEND003", _fired(analyze_bytes(raw)))

    def test_lookalike_sender_domain(self) -> None:
        raw = b"From: security@paypa1.com\nSubject: t\n\nbody\n"
        self.assertIn("SEND004", _fired(analyze_bytes(raw)))

    def test_executive_from_freemail(self) -> None:
        raw = (b'From: "Jane Doe | CEO" <jane.doe.ceo@gmail.com>\n'
               b"To: ap@example.com\nSubject: Quick request\n\n"
               b"Are you available? I need a favor.\n")
        self.assertIn("SEND005", _fired(analyze_bytes(raw)))


class TestURLRules(unittest.TestCase):
    def _html(self, body: str) -> set[str]:
        raw = (b'From: a@example.com\nSubject: t\nContent-Type: text/html\n\n'
               + body.encode())
        return _fired(analyze_bytes(raw))

    def test_anchor_mismatch(self) -> None:
        fired = self._html('<a href="https://evil.example.net/x">https://www.paypal.com</a>')
        self.assertIn("URL001", fired)

    def test_embedded_credentials(self) -> None:
        fired = self._html('<a href="https://paypal.com@evil.example.net/x">go</a>')
        self.assertIn("URL002", fired)

    def test_ip_literal_link(self) -> None:
        self.assertIn("URL003", self._html('<a href="http://45.132.19.204/login">go</a>'))

    def test_shortener(self) -> None:
        self.assertIn("URL006", self._html('<a href="https://bit.ly/abc">go</a>'))

    def test_javascript_uri(self) -> None:
        self.assertIn("URL012", self._html('<a href="javascript:alert(1)">go</a>'))

    def test_clean_link_fires_no_url_rules(self) -> None:
        fired = self._html('<a href="https://example.com/docs">docs</a>')
        self.assertFalse({f for f in fired if f.startswith("URL")})


class TestContentRules(unittest.TestCase):
    def _body(self, text: str) -> set[str]:
        raw = b"From: a@example.com\nSubject: t\n\n" + text.encode()
        return _fired(analyze_bytes(raw))

    def test_urgency(self) -> None:
        self.assertIn("CONT001", self._body("This is urgent, act now."))

    def test_threat(self) -> None:
        self.assertIn("CONT002", self._body("Your account will be suspended."))

    def test_credential_request(self) -> None:
        self.assertIn("CONT003", self._body("Please verify your account today."))

    def test_financial(self) -> None:
        self.assertIn("CONT004", self._body("Send a wire transfer to the new bank details."))

    def test_credential_form_in_html(self) -> None:
        raw = (b'From: a@example.com\nSubject: t\nContent-Type: text/html\n\n'
               b'<form action="https://evil.example/p"><input type="password"></form>')
        self.assertIn("CONT005", _fired(analyze_bytes(raw)))

    def test_hidden_text(self) -> None:
        raw = (b'From: a@example.com\nSubject: t\nContent-Type: text/html\n\n'
               b'<p style="font-size:0">hidden filler words</p>')
        self.assertIn("CONT006", _fired(analyze_bytes(raw)))

    def test_generic_greeting(self) -> None:
        self.assertIn("CONT008", self._body("Dear Customer, please read."))

    def test_fake_reply_thread(self) -> None:
        raw = b"From: a@example.com\nSubject: Re: Payment\n\nbody\n"
        self.assertIn("CONT009", _fired(analyze_bytes(raw)))

    def test_real_reply_thread_does_not_fire(self) -> None:
        raw = (b"From: a@example.com\nSubject: Re: Payment\n"
               b"In-Reply-To: <prev@example.com>\n\nbody\n")
        self.assertNotIn("CONT009", _fired(analyze_bytes(raw)))

    def test_neutral_text_fires_no_content_rules(self) -> None:
        fired = self._body("Here are the meeting notes from this morning.")
        self.assertFalse({f for f in fired if f.startswith("CONT")})


class TestAttachmentRules(unittest.TestCase):
    def _with_attachment(self, filename: str, content_type: str = "application/octet-stream") -> set[str]:
        raw = (
            b"From: a@example.com\nSubject: t\nMIME-Version: 1.0\n"
            b'Content-Type: multipart/mixed; boundary="B"\n\n--B\n'
            b"Content-Type: text/plain\n\ntext\n--B\n"
            + f'Content-Type: {content_type}; name="{filename}"\n'.encode()
            + f'Content-Disposition: attachment; filename="{filename}"\n'.encode()
            + b"Content-Transfer-Encoding: base64\n\nSGVsbG8=\n--B--\n"
        )
        return _fired(analyze_bytes(raw))

    def test_executable(self) -> None:
        self.assertIn("ATT001", self._with_attachment("payload.exe"))

    def test_macro_document(self) -> None:
        self.assertIn("ATT002", self._with_attachment("invoice.docm"))

    def test_double_extension(self) -> None:
        fired = self._with_attachment("Invoice.pdf.exe")
        self.assertIn("ATT003", fired)
        self.assertIn("ATT001", fired)

    def test_archive(self) -> None:
        self.assertIn("ATT004", self._with_attachment("files.zip"))

    def test_html_attachment(self) -> None:
        self.assertIn("ATT005", self._with_attachment("portal.html", "text/html"))

    def test_benign_pdf_fires_no_attachment_rules(self) -> None:
        fired = self._with_attachment("report.pdf", "application/pdf")
        self.assertFalse({f for f in fired if f.startswith("ATT")})


class TestScoring(unittest.TestCase):
    def test_category_caps_are_applied(self) -> None:
        analysis = analyze_bytes(_load_sample("01_credential_phish_m365.eml"))
        for category, total in analysis.categories.items():
            capped = min(total, CATEGORY_CAPS[category])
            self.assertLessEqual(capped, CATEGORY_CAPS[category])
        self.assertTrue(any("capped" in line for line in analysis.score_breakdown))

    def test_score_is_bounded(self) -> None:
        for name in _sample_names():
            with self.subTest(sample=name):
                analysis = analyze_bytes(_load_sample(name))
                self.assertGreaterEqual(analysis.score, 0)
                self.assertLessEqual(analysis.score, 100)

    def test_full_auth_pass_produces_mitigation(self) -> None:
        analysis = analyze_bytes(BENIGN)
        self.assertTrue(any("SPF, DKIM and DMARC all pass" in m for m in analysis.mitigations))

    def test_bulk_credit_requires_authentication(self) -> None:
        """A phisher adding List-Unsubscribe must not earn the bulk discount."""
        raw = (b"From: a@evil.example\nSubject: t\n"
               b"List-Unsubscribe: <https://evil.example/u>\n"
               b"Authentication-Results: mx; spf=fail; dmarc=fail\n\n"
               b"Verify your account now, urgent.\n")
        analysis = analyze_bytes(raw)
        self.assertFalse(any("bulk-mail headers" in m for m in analysis.mitigations))

    def test_hard_signal_prevents_benign_verdict(self) -> None:
        """Executable attachment plus perfect auth must still warrant review."""
        raw = (
            b"From: a@example.com\nSubject: t\n"
            b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
            b'MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="B"\n\n--B\n'
            b"Content-Type: text/plain\n\nhi\n--B\n"
            b'Content-Type: application/octet-stream; name="a.exe"\n'
            b'Content-Disposition: attachment; filename="a.exe"\n\nx\n--B--\n'
        )
        analysis = analyze_bytes(raw)
        self.assertIn("ATT001", _fired(analysis))
        self.assertNotEqual(analysis.verdict, "BENIGN")

    def test_disabled_rules_are_skipped(self) -> None:
        raw = b"From: a@example.com\nSubject: t\n\nThis is urgent, act now.\n"
        self.assertIn("CONT001", _fired(analyze_bytes(raw)))
        self.assertNotIn("CONT001", _fired(analyze_bytes(raw, disabled={"CONT001"})))

    def test_worse_of(self) -> None:
        self.assertEqual(worse_of("LOW", "HIGH"), "HIGH")
        self.assertEqual(worse_of("CRITICAL", "BENIGN"), "CRITICAL")


class TestRuleIntegrity(unittest.TestCase):
    def test_rule_ids_are_unique(self) -> None:
        ids = [r.id for r in ALL_RULES + CONTEXT_RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_no_single_rule_can_reach_critical(self) -> None:
        """A verdict should always need corroboration from more than one rule."""
        for rule in ALL_RULES:
            with self.subTest(rule=rule.id):
                self.assertLess(rule.weight, 80)

    def test_every_rule_has_a_description(self) -> None:
        for rule in ALL_RULES + CONTEXT_RULES:
            with self.subTest(rule=rule.id):
                self.assertTrue(rule.description.strip())
                self.assertTrue(rule.name.strip())

    def test_hard_signals_reference_real_rules(self) -> None:
        known = {r.id for r in ALL_RULES}
        self.assertTrue(HARD_SIGNALS <= known)

    def test_every_category_has_a_cap(self) -> None:
        for rule in ALL_RULES:
            with self.subTest(rule=rule.id):
                self.assertIn(rule.category, CATEGORY_CAPS)

    def test_no_rule_raises_on_empty_message(self) -> None:
        analysis = analyze(parse_bytes(b""), source="empty")
        self.assertFalse([f for f in analysis.findings if f.errored])

    def test_no_rule_raises_on_samples(self) -> None:
        for name in _sample_names():
            with self.subTest(sample=name):
                analysis = analyze_bytes(_load_sample(name), source=name)
                errored = [f.rule_id for f in analysis.findings if f.errored]
                self.assertEqual(errored, [], f"rules errored: {errored}")


class TestSampleCorpusRegression(unittest.TestCase):
    """Pins the verdict for each shipped sample so scoring changes are visible."""

    EXPECTED = {
        "01_credential_phish_m365.eml": "CRITICAL",
        "02_bec_ceo_wire_fraud.eml": "HIGH",
        "03_malware_invoice.eml": "CRITICAL",
        "04_legitimate_github.eml": "BENIGN",
        "05_legitimate_newsletter.eml": "BENIGN",
        "06_homograph_paypal.eml": "CRITICAL",
    }

    def test_verdicts_match_expectations(self) -> None:
        for name, expected in self.EXPECTED.items():
            with self.subTest(sample=name):
                analysis = analyze_bytes(_load_sample(name), source=name)
                self.assertEqual(
                    analysis.verdict, expected,
                    f"{name}: expected {expected}, got {analysis.verdict} "
                    f"(score {analysis.score}, rules {sorted(_fired(analysis))})",
                )

    def test_malicious_samples_produce_actions_and_iocs(self) -> None:
        for name in ("01_credential_phish_m365.eml", "06_homograph_paypal.eml"):
            with self.subTest(sample=name):
                analysis = analyze_bytes(_load_sample(name), source=name)
                self.assertTrue(analysis.iocs.urls)
                self.assertTrue(analysis.recommended_actions())
                self.assertTrue(analysis.mitre_techniques)

    def test_legitimate_samples_have_no_hard_signals(self) -> None:
        for name in ("04_legitimate_github.eml", "05_legitimate_newsletter.eml"):
            with self.subTest(sample=name):
                analysis = analyze_bytes(_load_sample(name), source=name)
                self.assertFalse(_fired(analysis) & HARD_SIGNALS)

    def test_analysis_is_json_serializable(self) -> None:
        import json

        for name in _sample_names():
            with self.subTest(sample=name):
                payload = analyze_bytes(_load_sample(name), source=name).to_dict()
                json.dumps(payload, default=str)


def _sample_names() -> list[str]:
    return sorted(n for n in os.listdir(SAMPLES_DIR) if n.endswith(".eml"))


def _load_sample(name: str) -> bytes:
    with open(os.path.join(SAMPLES_DIR, name), "rb") as handle:
        return handle.read()


if __name__ == "__main__":
    unittest.main()
