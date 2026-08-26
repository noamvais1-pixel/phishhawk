"""Tests for IOC extraction, URL forensics and look-alike domain detection."""

from __future__ import annotations

import unittest

from phishhawk.iocs import (
    analyze_url,
    decode_idna,
    defang,
    extract_iocs,
    html_to_text,
    levenshtein,
    looks_like_brand,
    merge_iocs,
    skeleton,
)
from phishhawk.parser import parse_bytes


def _flags(url: str, anchor: str = "") -> list[str]:
    return analyze_url(url, anchor_text=anchor).flags


class TestURLFlags(unittest.TestCase):
    def test_ip_literal_host(self) -> None:
        self.assertIn("ip-literal-host", _flags("http://192.0.2.5/login"))

    def test_embedded_credentials(self) -> None:
        self.assertIn(
            "embedded-credentials",
            _flags("https://www.paypal.com@evil.example.net/signin"),
        )

    def test_embedded_credentials_resolves_real_host(self) -> None:
        info = analyze_url("https://www.paypal.com@evil.example.net/signin")
        self.assertEqual(info.host, "evil.example.net")

    def test_punycode_host(self) -> None:
        self.assertIn("punycode-host", _flags("https://xn--pypal-4ve.com/login"))

    def test_url_shortener(self) -> None:
        self.assertIn("url-shortener", _flags("https://bit.ly/3xKq9Zp"))

    def test_suspicious_tld(self) -> None:
        self.assertIn("suspicious-tld", _flags("https://free-gift.top/claim"))

    def test_nonstandard_port(self) -> None:
        self.assertIn("nonstandard-port", _flags("http://example.com:8080/x"))

    def test_standard_ports_not_flagged(self) -> None:
        self.assertNotIn("nonstandard-port", _flags("https://example.com:443/x"))

    def test_credential_path(self) -> None:
        self.assertIn("credential-path", _flags("https://example.com/account/verify"))

    def test_recipient_in_url(self) -> None:
        self.assertIn(
            "recipient-in-url", _flags("https://example.com/a?u=victim@corp.example")
        )

    def test_open_redirect_param(self) -> None:
        self.assertIn(
            "open-redirect-param",
            _flags("https://trusted.example.com/r?url=https://evil.example.net"),
        )

    def test_abused_hosting(self) -> None:
        self.assertIn(
            "abused-hosting", _flags("https://phish-kit.web.app/login")
        )

    def test_cleartext_http(self) -> None:
        self.assertIn("cleartext-http", _flags("http://example.com/"))

    def test_deep_subdomain(self) -> None:
        self.assertIn("deep-subdomain", _flags("https://a.b.c.d.e.example.com/"))

    def test_clean_url_has_no_alarming_flags(self) -> None:
        flags = _flags("https://github.com/example/repo/pull/142")
        self.assertEqual(flags, [])

    def test_trailing_punctuation_is_stripped(self) -> None:
        self.assertEqual(
            analyze_url("https://example.com/page.").url, "https://example.com/page"
        )


class TestAnchorMismatch(unittest.TestCase):
    def test_mismatch_detected(self) -> None:
        flags = _flags("https://evil.example.net/go", anchor="https://www.paypal.com/signin")
        self.assertIn("anchor-text-mismatch", flags)

    def test_bare_domain_text_mismatch(self) -> None:
        flags = _flags("https://evil.example.net/go", anchor="paypal.com")
        self.assertIn("anchor-text-mismatch", flags)

    def test_matching_anchor_not_flagged(self) -> None:
        flags = _flags("https://example.com/a", anchor="https://example.com/a")
        self.assertNotIn("anchor-text-mismatch", flags)

    def test_subdomain_of_same_site_not_flagged(self) -> None:
        flags = _flags("https://www.example.com/a", anchor="https://mail.example.com/b")
        self.assertNotIn("anchor-text-mismatch", flags)

    def test_non_url_anchor_text_ignored(self) -> None:
        flags = _flags("https://example.com/a", anchor="Click here to continue")
        self.assertNotIn("anchor-text-mismatch", flags)


class TestBrandLookalike(unittest.TestCase):
    LEGIT = [
        "login.microsoftonline.com", "github.com", "notifications.github.com",
        "amazon.co.uk", "paypal.com", "google.com", "dropbox.com",
        "example.com", "mail.retailer-example.com", "linkedin.com",
    ]
    SPOOFED = [
        ("micros0ft-support.com", "microsoft"),
        ("paypa1.com", "paypal"),
        ("xn--pypal-4ve.com", "paypal"),
        ("secure-paypal-login.xyz", "paypal"),
        ("netfIix.com", "netflix"),
        ("arnazon.com", "amazon"),
        ("accounts-paypal.firebaseapp.com", "paypal"),
    ]

    def test_no_false_positives_on_real_brand_domains(self) -> None:
        for host in self.LEGIT:
            with self.subTest(host=host):
                self.assertIsNone(looks_like_brand(host))

    def test_spoofed_domains_detected(self) -> None:
        for host, brand in self.SPOOFED:
            with self.subTest(host=host):
                result = looks_like_brand(host)
                self.assertIsNotNone(result, f"{host} should have been flagged")
                assert result is not None
                self.assertEqual(result[0], brand)

    def test_punycode_is_decoded(self) -> None:
        self.assertEqual(decode_idna("xn--pypal-4ve.com"), "pаypal.com")
        self.assertEqual(decode_idna("example.com"), "example.com")

    def test_decode_idna_survives_malformed_input(self) -> None:
        self.assertEqual(decode_idna("xn--.com"), "xn--.com")

    def test_skeleton_collapses_homoglyphs(self) -> None:
        self.assertEqual(skeleton("arnazon"), "amazon")
        self.assertEqual(skeleton("vvhatsapp"), "whatsapp")
        self.assertEqual(skeleton("paypa1"), "paypal")


class TestLevenshtein(unittest.TestCase):
    def test_known_distances(self) -> None:
        self.assertEqual(levenshtein("kitten", "sitting"), 3)
        self.assertEqual(levenshtein("abc", "abc"), 0)
        self.assertEqual(levenshtein("paypal", "paypa1"), 1)

    def test_short_circuits_beyond_limit(self) -> None:
        self.assertGreater(levenshtein("a" * 40, "b" * 2, max_distance=3), 3)


class TestDefang(unittest.TestCase):
    def test_scheme_and_dots_neutralized(self) -> None:
        self.assertEqual(
            defang("https://evil.example.com/a"), "hxxps[://]evil[.]example[.]com/a"
        )
        self.assertEqual(defang("http://a.b/c"), "hxxp[://]a[.]b/c")

    def test_at_sign_neutralized(self) -> None:
        self.assertEqual(defang("bad@evil.com"), "bad[at]evil[.]com")

    def test_defanged_output_is_not_clickable(self) -> None:
        self.assertNotIn("http://", defang("http://x.example"))
        self.assertNotIn("https://", defang("https://x.example"))


class TestHTMLHandling(unittest.TestCase):
    def test_script_and_style_removed(self) -> None:
        html = "<style>p{color:red}</style><script>evil()</script><p>Visible</p>"
        text = html_to_text(html)
        self.assertIn("Visible", text)
        self.assertNotIn("evil()", text)
        self.assertNotIn("color:red", text)

    def test_entities_unescaped(self) -> None:
        self.assertIn("A & B", html_to_text("<p>A &amp; B</p>"))


class TestExtraction(unittest.TestCase):
    # 45.132.19.204 is globally routable. RFC 5737 documentation ranges
    # (192.0.2/24, 198.51.100/24, 203.0.113/24) cannot be used here: Python's
    # ipaddress module reports them as private, so the extractor filters them
    # out along with real internal addresses.
    RAW = b"""From: "Sender" <sender@example.com>
Reply-To: other@elsewhere.example
To: victim@corp.example
Subject: Test
Content-Type: text/html; charset="utf-8"

<html><body>
<a href="https://evil.example.net/login">https://www.paypal.com</a>
<a href="mailto:reply@evil.example.net">mail us</a>
<a href="javascript:alert(1)">run</a>
<p>Contact 45.132.19.204 or admin@third.example</p>
</body></html>
"""

    def setUp(self) -> None:
        self.iocs = extract_iocs(parse_bytes(self.RAW))

    def test_urls_collected(self) -> None:
        urls = {u.url for u in self.iocs.urls}
        self.assertIn("https://evil.example.net/login", urls)

    def test_javascript_uri_flagged(self) -> None:
        flags = [f for u in self.iocs.urls for f in u.flags]
        self.assertIn("javascript-uri", flags)

    def test_emails_collected_from_headers_and_body(self) -> None:
        self.assertIn("sender@example.com", self.iocs.emails)
        self.assertIn("other@elsewhere.example", self.iocs.emails)
        self.assertIn("admin@third.example", self.iocs.emails)
        self.assertIn("reply@evil.example.net", self.iocs.emails)

    def test_public_ip_collected(self) -> None:
        self.assertIn("45.132.19.204", self.iocs.ips)

    def test_private_ips_excluded(self) -> None:
        raw = b"From: a@b.example\nSubject: x\n\nInternal host 192.168.1.10 and 10.0.0.5\n"
        iocs = extract_iocs(parse_bytes(raw))
        self.assertEqual(iocs.ips, set())

    def test_loopback_and_reserved_excluded(self) -> None:
        raw = b"From: a@b.example\nSubject: x\n\nHosts 127.0.0.1 and 0.0.0.0 and 255.255.255.255\n"
        self.assertEqual(extract_iocs(parse_bytes(raw)).ips, set())

    def test_defanged_view_has_no_live_urls(self) -> None:
        for value in self.iocs.defanged()["urls"]:
            self.assertNotIn("https://", value)

    def test_merge_deduplicates(self) -> None:
        merged = merge_iocs([self.iocs, self.iocs])
        self.assertEqual(len(merged.urls), len(self.iocs.urls))
        self.assertEqual(merged.emails, self.iocs.emails)


if __name__ == "__main__":
    unittest.main()
