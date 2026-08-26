"""RFC-822 / MIME parsing for PhishHawk.

Turns raw ``.eml`` bytes into a :class:`ParsedEmail` — a flat, analysis-friendly
view of the headers, bodies, attachments and delivery chain. Nothing in this
module makes network calls or judges the message; it only reports what is there.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any

# Multi-label public suffixes we care about. Not exhaustive (that would need the
# full Public Suffix List), but it covers the ccTLD shapes that show up in real
# phishing corpora, which is what the registrable-domain comparison needs.
MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
        "co.il", "org.il", "ac.il", "gov.il", "net.il", "muni.il", "idf.il",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "com.br", "net.br", "org.br", "gov.br",
        "co.in", "net.in", "org.in", "gov.in", "ac.in",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
        "co.za", "org.za", "net.za", "gov.za",
        "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw",
        "co.nz", "net.nz", "org.nz", "govt.nz",
        "co.kr", "or.kr", "go.kr",
        "com.ua", "com.pl", "com.ru", "org.ru", "net.ru",
        "com.es", "com.pt", "com.gr", "com.my", "com.ph", "com.vn",
    }
)

_ADDR_HEADERS = ("from", "to", "cc", "bcc", "reply-to", "sender", "return-path")

_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc|compauth)=([a-z]+)", re.IGNORECASE)
_RECEIVED_FROM_RE = re.compile(r"^\s*from\s+([^\s;(]+)", re.IGNORECASE)
_RECEIVED_BY_RE = re.compile(r"\bby\s+([^\s;(]+)", re.IGNORECASE)
_RECEIVED_IP_RE = re.compile(r"[\[(]\s*(?:IPv6:)?([0-9a-fA-F:.]{3,45})\s*[\])]")
_RECEIVED_WITH_RE = re.compile(r"\bwith\s+([A-Za-z0-9/_.-]+)", re.IGNORECASE)


def registrable_domain(host: str) -> str:
    """Reduce a hostname to its registrable ("organizational") domain.

    ``mail.corp.example.co.uk`` -> ``example.co.uk``. Bare IPs are returned
    unchanged so callers can still compare them meaningfully.
    """
    host = (host or "").strip().strip(".").lower()
    if not host:
        return ""
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if _is_ip_literal(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_ip_literal(value: str) -> bool:
    if ":" in value:
        return all(c in "0123456789abcdefABCDEF:." for c in value)
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def decode_mime_words(value: str | None) -> str:
    """Decode RFC 2047 encoded-words, falling back to the raw string."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


@dataclass
class Attachment:
    """One MIME part that is presented to the user as a file."""

    filename: str
    content_type: str
    size: int
    sha256: str
    content_disposition: str = ""
    is_inline: bool = False

    @property
    def extension(self) -> str:
        name = self.filename.rsplit("/", 1)[-1]
        return name.rsplit(".", 1)[-1].lower() if "." in name else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size": self.size,
            "sha256": self.sha256,
            "extension": self.extension,
            "is_inline": self.is_inline,
        }


@dataclass
class ReceivedHop:
    """A single ``Received:`` header, parsed into its useful pieces.

    ``index`` counts from the originating hop (0) outward, so hop 0 is the
    oldest header — the one closest to the real sender.
    """

    index: int
    raw: str
    from_host: str = ""
    by_host: str = ""
    ip: str = ""
    protocol: str = ""
    timestamp: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "from_host": self.from_host,
            "by_host": self.by_host,
            "ip": self.ip,
            "protocol": self.protocol,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


@dataclass
class ParsedEmail:
    """A normalized, analysis-ready view of one message."""

    raw_size: int = 0
    sha256: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    subject: str = ""
    message_id: str = ""
    date: datetime | None = None
    date_raw: str = ""
    from_addrs: list[tuple[str, str]] = field(default_factory=list)
    to_addrs: list[tuple[str, str]] = field(default_factory=list)
    cc_addrs: list[tuple[str, str]] = field(default_factory=list)
    reply_to_addrs: list[tuple[str, str]] = field(default_factory=list)
    return_path: str = ""
    text_body: str = ""
    html_body: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    received_chain: list[ReceivedHop] = field(default_factory=list)
    auth_results: dict[str, str] = field(default_factory=dict)
    parse_errors: list[str] = field(default_factory=list)

    # -- convenience accessors -------------------------------------------------

    def header(self, name: str) -> str:
        """First value of ``name``, decoded. Empty string when absent."""
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return ""

    def header_all(self, name: str) -> list[str]:
        lowered = name.lower()
        return [v for k, v in self.headers if k.lower() == lowered]

    def has_header(self, name: str) -> bool:
        lowered = name.lower()
        return any(k.lower() == lowered for k, _ in self.headers)

    @property
    def from_address(self) -> str:
        return self.from_addrs[0][1] if self.from_addrs else ""

    @property
    def from_display_name(self) -> str:
        return self.from_addrs[0][0] if self.from_addrs else ""

    @property
    def from_domain(self) -> str:
        return domain_of(self.from_address)

    @property
    def body(self) -> str:
        """Text body when present, else the HTML source."""
        return self.text_body or self.html_body

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "raw_size": self.raw_size,
            "subject": self.subject,
            "message_id": self.message_id,
            "date": self.date.isoformat() if self.date else None,
            "from": [{"name": n, "address": a} for n, a in self.from_addrs],
            "to": [{"name": n, "address": a} for n, a in self.to_addrs],
            "cc": [{"name": n, "address": a} for n, a in self.cc_addrs],
            "reply_to": [{"name": n, "address": a} for n, a in self.reply_to_addrs],
            "return_path": self.return_path,
            "auth_results": self.auth_results,
            "received_chain": [h.to_dict() for h in self.received_chain],
            "attachments": [a.to_dict() for a in self.attachments],
            "has_text_body": bool(self.text_body),
            "has_html_body": bool(self.html_body),
            "parse_errors": self.parse_errors,
        }


def domain_of(address: str) -> str:
    """Lowercased domain part of an email address, or empty string."""
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().strip(">").lower()


def parse_file(path: str) -> ParsedEmail:
    """Parse an ``.eml`` file from disk."""
    with open(path, "rb") as handle:
        return parse_bytes(handle.read())


def parse_bytes(raw: bytes) -> ParsedEmail:
    """Parse raw message bytes. Never raises on malformed input."""
    result = ParsedEmail(raw_size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    try:
        message = email.message_from_bytes(raw, policy=email.policy.compat32)
    except Exception as exc:  # pragma: no cover - stdlib is very tolerant
        result.parse_errors.append(f"message parse failed: {exc}")
        return result

    _load_headers(message, result)
    _load_addresses(message, result)
    _load_bodies(message, result)
    _load_received_chain(result)
    _load_auth_results(result)
    return result


def _load_headers(message: Message, result: ParsedEmail) -> None:
    for key, value in message.items():
        result.headers.append((key, decode_mime_words(value)))

    result.subject = decode_mime_words(message.get("Subject", ""))
    result.message_id = (message.get("Message-ID", "") or "").strip()
    result.date_raw = (message.get("Date", "") or "").strip()
    if result.date_raw:
        try:
            parsed = parsedate_to_datetime(result.date_raw)
            if parsed is not None and parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            result.date = parsed
        except Exception:
            result.parse_errors.append(f"unparsable Date header: {result.date_raw!r}")

    return_path = (message.get("Return-Path", "") or "").strip()
    result.return_path = return_path.strip("<>").strip().lower()


def _load_addresses(message: Message, result: ParsedEmail) -> None:
    buckets = {
        "from": result.from_addrs,
        "to": result.to_addrs,
        "cc": result.cc_addrs,
        "reply-to": result.reply_to_addrs,
    }
    for header_name, bucket in buckets.items():
        raw_values = message.get_all(header_name, [])
        if not raw_values:
            continue
        decoded = [decode_mime_words(v) for v in raw_values]
        for name, addr in getaddresses(decoded):
            addr = (addr or "").strip().lower()
            if addr or name:
                bucket.append((decode_mime_words(name).strip(), addr))


def _load_bodies(message: Message, result: ParsedEmail) -> None:
    for part in message.walk():
        if part.is_multipart():
            continue

        content_type = (part.get_content_type() or "").lower()
        disposition = (part.get("Content-Disposition", "") or "").lower()
        filename = decode_mime_words(part.get_filename())

        try:
            payload = part.get_payload(decode=True)
        except Exception as exc:
            result.parse_errors.append(f"payload decode failed for {content_type}: {exc}")
            continue
        if payload is None:
            continue

        is_attachment = "attachment" in disposition or bool(filename)
        if not is_attachment and content_type in ("text/plain", "text/html"):
            text = _decode_text(part, payload, result)
            if content_type == "text/plain":
                result.text_body += text
            else:
                result.html_body += text
            continue

        if not is_attachment and content_type.startswith("text/"):
            continue

        result.attachments.append(
            Attachment(
                filename=filename or "(unnamed)",
                content_type=content_type,
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
                content_disposition=disposition.split(";", 1)[0].strip(),
                is_inline="inline" in disposition,
            )
        )


def _decode_text(part: Message, payload: bytes, result: ParsedEmail) -> str:
    charset = part.get_content_charset() or "utf-8"
    for candidate in (charset, "utf-8", "latin-1"):
        try:
            return payload.decode(candidate)
        except (UnicodeDecodeError, LookupError):
            continue
    result.parse_errors.append("body decoded with replacement characters")
    return payload.decode("utf-8", errors="replace")


def _load_received_chain(result: ParsedEmail) -> None:
    # Received headers are prepended by each hop, so the last one in the list is
    # the oldest. Reversing gives origin-first ordering, which is how analysts
    # read a delivery chain.
    raw_hops = list(reversed(result.header_all("Received")))
    for index, raw in enumerate(raw_hops):
        collapsed = " ".join(raw.split())
        hop = ReceivedHop(index=index, raw=collapsed)

        if match := _RECEIVED_FROM_RE.search(collapsed):
            hop.from_host = match.group(1).strip("[]<>").lower()
        if match := _RECEIVED_BY_RE.search(collapsed):
            hop.by_host = match.group(1).strip("[]<>").lower()
        if match := _RECEIVED_IP_RE.search(collapsed):
            hop.ip = match.group(1)
        if match := _RECEIVED_WITH_RE.search(collapsed):
            hop.protocol = match.group(1).upper()

        if ";" in collapsed:
            date_part = collapsed.rsplit(";", 1)[1].strip()
            try:
                stamp = parsedate_to_datetime(date_part)
                if stamp is not None and stamp.tzinfo is None:
                    stamp = stamp.replace(tzinfo=timezone.utc)
                hop.timestamp = stamp
            except Exception:
                pass

        result.received_chain.append(hop)


def _load_auth_results(result: ParsedEmail) -> None:
    blob = " ".join(
        result.header_all("Authentication-Results")
        + result.header_all("ARC-Authentication-Results")
        + result.header_all("Received-SPF")
    )
    for mechanism, verdict in _AUTH_RE.findall(blob):
        mechanism = mechanism.lower()
        # First verdict wins: the receiving MTA writes its own result first.
        result.auth_results.setdefault(mechanism, verdict.lower())

    if "spf" not in result.auth_results and result.has_header("Received-SPF"):
        first_word = result.header("Received-SPF").strip().split(" ", 1)[0].lower()
        if first_word:
            result.auth_results["spf"] = first_word
