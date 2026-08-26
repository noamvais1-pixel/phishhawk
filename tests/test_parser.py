"""Tests for MIME parsing, header normalization and the delivery chain."""

from __future__ import annotations

import unittest

from phishhawk.parser import (
    domain_of,
    parse_bytes,
    registrable_domain,
    decode_mime_words,
)

SIMPLE = b"""From: "Alice Smith" <alice@example.com>
To: bob@example.org
Subject: Hello there
Date: Mon, 11 Aug 2025 09:31:45 +0000
Message-ID: <abc123@example.com>

Plain body text.
"""

MULTIPART = b"""From: sender@example.com
To: rcpt@example.org
Subject: With attachment
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND"

--BOUND
Content-Type: text/plain; charset="utf-8"

Text part.
--BOUND
Content-Type: text/html; charset="utf-8"

<html><body><p>HTML part</p></body></html>
--BOUND
Content-Type: application/pdf; name="doc.pdf"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="doc.pdf"

SGVsbG8gUERG
--BOUND--
"""

CHAIN = b"""Received: from last.example.net (last.example.net [203.0.113.9])
 by mx.example.com with ESMTPS id AAA; Tue, 12 Aug 2025 03:14:22 -0700
Received: from first.example.org (first.example.org [198.51.100.7])
 by last.example.net with SMTP id BBB; Tue, 12 Aug 2025 03:14:18 -0700
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.org;
 dkim=fail header.d=example.org; dmarc=fail header.from=example.org
From: x@example.org
Subject: Chain test

body
"""


class TestBasicParsing(unittest.TestCase):
    def test_headers_and_addresses(self) -> None:
        parsed = parse_bytes(SIMPLE)
        self.assertEqual(parsed.subject, "Hello there")
        self.assertEqual(parsed.from_address, "alice@example.com")
        self.assertEqual(parsed.from_display_name, "Alice Smith")
        self.assertEqual(parsed.from_domain, "example.com")
        self.assertEqual(parsed.to_addrs[0][1], "bob@example.org")
        self.assertEqual(parsed.message_id, "<abc123@example.com>")
        self.assertIn("Plain body text.", parsed.text_body)

    def test_date_is_timezone_aware(self) -> None:
        parsed = parse_bytes(SIMPLE)
        self.assertIsNotNone(parsed.date)
        assert parsed.date is not None
        self.assertIsNotNone(parsed.date.tzinfo)

    def test_sha256_and_size_recorded(self) -> None:
        parsed = parse_bytes(SIMPLE)
        self.assertEqual(len(parsed.sha256), 64)
        self.assertEqual(parsed.raw_size, len(SIMPLE))

    def test_header_lookup_is_case_insensitive(self) -> None:
        parsed = parse_bytes(SIMPLE)
        self.assertEqual(parsed.header("SUBJECT"), "Hello there")
        self.assertTrue(parsed.has_header("message-id"))
        self.assertEqual(parsed.header("X-Absent"), "")

    def test_empty_input_does_not_raise(self) -> None:
        parsed = parse_bytes(b"")
        self.assertEqual(parsed.subject, "")
        self.assertEqual(parsed.from_address, "")

    def test_garbage_input_does_not_raise(self) -> None:
        parsed = parse_bytes(b"\x00\xff\xfe not an email at all \x00")
        self.assertIsNotNone(parsed)


class TestMultipart(unittest.TestCase):
    def test_bodies_and_attachment_split(self) -> None:
        parsed = parse_bytes(MULTIPART)
        self.assertIn("Text part.", parsed.text_body)
        self.assertIn("HTML part", parsed.html_body)
        self.assertEqual(len(parsed.attachments), 1)

        attachment = parsed.attachments[0]
        self.assertEqual(attachment.filename, "doc.pdf")
        self.assertEqual(attachment.extension, "pdf")
        self.assertEqual(attachment.content_type, "application/pdf")
        self.assertEqual(len(attachment.sha256), 64)

    def test_body_property_prefers_text(self) -> None:
        parsed = parse_bytes(MULTIPART)
        self.assertIn("Text part.", parsed.body)


class TestDeliveryChain(unittest.TestCase):
    def test_chain_is_ordered_origin_first(self) -> None:
        parsed = parse_bytes(CHAIN)
        self.assertEqual(len(parsed.received_chain), 2)
        self.assertEqual(parsed.received_chain[0].from_host, "first.example.org")
        self.assertEqual(parsed.received_chain[1].from_host, "last.example.net")

    def test_hop_fields_extracted(self) -> None:
        hop = parse_bytes(CHAIN).received_chain[0]
        self.assertEqual(hop.ip, "198.51.100.7")
        self.assertEqual(hop.by_host, "last.example.net")
        self.assertEqual(hop.protocol, "SMTP")
        self.assertIsNotNone(hop.timestamp)

    def test_auth_results_parsed(self) -> None:
        parsed = parse_bytes(CHAIN)
        self.assertEqual(parsed.auth_results["spf"], "pass")
        self.assertEqual(parsed.auth_results["dkim"], "fail")
        self.assertEqual(parsed.auth_results["dmarc"], "fail")


class TestDomainHelpers(unittest.TestCase):
    def test_registrable_domain(self) -> None:
        cases = {
            "mail.corp.example.com": "example.com",
            "example.com": "example.com",
            "a.b.c.example.co.uk": "example.co.uk",
            "example.co.il": "example.co.il",
            "sub.example.co.jp": "example.co.jp",
            "localhost": "localhost",
            "": "",
        }
        for host, expected in cases.items():
            with self.subTest(host=host):
                self.assertEqual(registrable_domain(host), expected)

    def test_registrable_domain_passes_ips_through(self) -> None:
        self.assertEqual(registrable_domain("192.0.2.1"), "192.0.2.1")

    def test_domain_of(self) -> None:
        self.assertEqual(domain_of("User@Example.COM"), "example.com")
        self.assertEqual(domain_of("not-an-address"), "")
        self.assertEqual(domain_of(""), "")


class TestEncodedHeaders(unittest.TestCase):
    def test_rfc2047_subject_is_decoded(self) -> None:
        raw = (
            b"From: a@example.com\n"
            b"Subject: =?utf-8?B?VXJnZW50OiB2ZXJpZnkgeW91ciBhY2NvdW50?=\n"
            b"\nbody\n"
        )
        self.assertEqual(parse_bytes(raw).subject, "Urgent: verify your account")

    def test_decode_mime_words_handles_none_and_plain(self) -> None:
        self.assertEqual(decode_mime_words(None), "")
        self.assertEqual(decode_mime_words("plain text"), "plain text")


if __name__ == "__main__":
    unittest.main()
