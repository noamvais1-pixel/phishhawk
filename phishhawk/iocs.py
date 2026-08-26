"""Indicator-of-compromise extraction and URL forensics.

Pulls URLs, domains, IPs, addresses and hashes out of a parsed message, then
annotates every URL with the properties that matter for phishing triage:
redirectors, IP literals, punycode, embedded credentials, shortener services
and mismatches between an HTML anchor's text and its real destination.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from html import unescape
from typing import Any, Iterable
from urllib.parse import unquote, urlsplit

from phishhawk.parser import ParsedEmail, registrable_domain

# TLDs with a persistently poor reputation / very low registration cost. Presence
# is a weak signal on its own, which is why the analyzer scores it low.
SUSPICIOUS_TLDS = frozenset(
    {
        "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click",
        "link", "work", "loan", "download", "review", "country", "stream", "gdn",
        "racing", "win", "bid", "date", "faith", "cricket", "science", "party",
        "accountant", "kim", "men", "trade", "webcam", "rest", "quest", "cyou",
        "sbs", "monster", "lol", "beauty", "hair", "skin", "bond", "autos",
    }
)

URL_SHORTENERS = frozenset(
    {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
        "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy",
        "tiny.cc", "lnkd.in", "db.tt", "qr.ae", "soo.gd", "s2r.co", "clicky.me",
        "bl.ink", "short.io", "t.ly", "shorte.st", "3.ly", "urlz.fr", "v.gd",
    }
)

# Services frequently abused to host credential-harvesting pages on a domain the
# recipient (and many mail filters) already trusts.
ABUSED_HOSTING = frozenset(
    {
        "firebasestorage.googleapis.com", "storage.googleapis.com",
        "s3.amazonaws.com", "blob.core.windows.net", "web.app", "firebaseapp.com",
        "weebly.com", "wixsite.com", "glitch.me", "repl.co", "netlify.app",
        "vercel.app", "pages.dev", "workers.dev", "github.io", "gitbook.io",
        "sharepoint.com", "onedrive.live.com", "docs.google.com", "forms.gle",
        "sites.google.com", "notion.site", "typeform.com", "jotform.com",
        "codesandbox.io", "surge.sh", "000webhostapp.com", "duckdns.org",
    }
)

# Brands impersonated often enough to be worth a dedicated look-alike check.
WATCHED_BRANDS = (
    "microsoft", "office365", "outlook", "onedrive", "sharepoint", "google",
    "gmail", "apple", "icloud", "amazon", "paypal", "netflix", "facebook",
    "instagram", "linkedin", "whatsapp", "dropbox", "docusign", "adobe",
    "chase", "wellsfargo", "citibank", "hsbc", "barclays", "santander",
    "coinbase", "binance", "metamask", "blockchain", "steam", "roblox",
    "fedex", "dhl", "ups", "usps", "irs", "hmrc", "zoom", "slack", "github",
)

# Registrable domains the brands above genuinely operate. Without this, real
# infrastructure such as ``login.microsoftonline.com`` matches the "brand name
# appears in the domain" heuristic and every authentic notification is flagged.
BRAND_DOMAINS = frozenset(
    {
        "microsoft.com", "microsoftonline.com", "microsoft365.com", "office.com",
        "office365.com", "live.com", "outlook.com", "msn.com", "windows.net",
        "sharepoint.com", "onedrive.com", "azure.com", "msftauth.net", "msidentity.com",
        "google.com", "googlemail.com", "gmail.com", "googleapis.com", "youtube.com",
        "google.co.uk", "gstatic.com", "goo.gl", "withgoogle.com",
        "apple.com", "icloud.com", "me.com", "mac.com", "itunes.com",
        "amazon.com", "amazon.co.uk", "amazonaws.com", "amazon.jobs", "aws.amazon.com",
        "paypal.com", "paypal.me", "paypalobjects.com",
        "netflix.com", "nflxext.com",
        "facebook.com", "fb.com", "meta.com", "instagram.com", "whatsapp.com",
        "linkedin.com", "licdn.com", "lnkd.in",
        "dropbox.com", "dropboxmail.com", "docusign.com", "docusign.net",
        "adobe.com", "adobesign.com",
        "chase.com", "wellsfargo.com", "citibank.com", "citi.com", "hsbc.com",
        "hsbc.co.uk", "barclays.co.uk", "barclays.com", "santander.co.uk",
        "coinbase.com", "binance.com", "metamask.io", "blockchain.com",
        "steampowered.com", "steamcommunity.com", "roblox.com",
        "fedex.com", "dhl.com", "dhl.de", "ups.com", "usps.com", "usps.gov",
        "irs.gov", "hmrc.gov.uk", "gov.uk",
        "zoom.us", "zoom.com", "slack.com", "slack-edge.com",
        "github.com", "github.io", "githubusercontent.com",
    }
)

_URL_RE = re.compile(
    r"""(?xi)
    \b
    (
        (?:https?|ftp)://[^\s<>"'\)\]\}]+
        |
        www\.[^\s<>"'\)\]\}]+
    )
    """
)
_HREF_RE = re.compile(r"""(?is)<a\b[^>]*?href\s*=\s*(?P<q>["']?)(?P<url>[^"'\s>]+)(?P=q)[^>]*>(?P<text>.*?)</a\s*>""")
_TAG_RE = re.compile(r"(?s)<[^>]+>")
_SCRIPT_STYLE_RE = re.compile(r"(?is)<(script|style)\b.*?</\1\s*>")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Latin characters that Unicode look-alikes most commonly stand in for.
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ł": "l", "ο": "o", "ρ": "p",
    "α": "a", "ν": "v", "μ": "u", "τ": "t", "κ": "k", "ϲ": "c", "ԛ": "q",
    "ɑ": "a", "ᴏ": "o", "ʟ": "l", "ɪ": "i", "𝗮": "a", "0": "o", "1": "l",
}


@dataclass
class URLInfo:
    """One URL plus everything we can tell about it without touching the network."""

    url: str
    scheme: str = ""
    host: str = ""
    port: int | None = None
    path: str = ""
    query: str = ""
    domain: str = ""
    tld: str = ""
    anchor_text: str = ""
    source: str = "body"
    flags: list[str] = field(default_factory=list)

    def flag(self, name: str) -> None:
        if name not in self.flags:
            self.flags.append(name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "host": self.host,
            "domain": self.domain,
            "scheme": self.scheme,
            "tld": self.tld,
            "anchor_text": self.anchor_text,
            "source": self.source,
            "flags": self.flags,
        }


@dataclass
class IOCSet:
    """Every indicator lifted out of a single message."""

    urls: list[URLInfo] = field(default_factory=list)
    domains: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)
    hashes: dict[str, set[str]] = field(
        default_factory=lambda: {"md5": set(), "sha1": set(), "sha256": set()}
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "urls": [u.to_dict() for u in self.urls],
            "domains": sorted(self.domains),
            "ips": sorted(self.ips),
            "emails": sorted(self.emails),
            "hashes": {k: sorted(v) for k, v in self.hashes.items()},
        }

    def defanged(self) -> dict[str, list[str]]:
        """IOCs rewritten so they cannot be clicked — safe to paste into a ticket."""
        return {
            "urls": sorted({defang(u.url) for u in self.urls}),
            "domains": sorted(defang(d) for d in self.domains),
            "ips": sorted(defang(i) for i in self.ips),
            "emails": sorted(defang(e) for e in self.emails),
        }


def defang(value: str) -> str:
    """Neutralize an indicator: ``http://evil.com`` -> ``hxxp[://]evil[.]com``.

    Scheme markers are rewritten first and contain no dot, so the subsequent
    dot-bracketing cannot corrupt them.
    """
    out = value.replace("https://", "hxxps[://]").replace("http://", "hxxp[://]")
    out = out.replace("ftp://", "fxp[://]")
    return out.replace(".", "[.]").replace("@", "[at]")


def html_to_text(html: str) -> str:
    """Best-effort visible text from an HTML body."""
    stripped = _SCRIPT_STYLE_RE.sub(" ", html or "")
    stripped = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>", "\n", stripped)
    stripped = _TAG_RE.sub(" ", stripped)
    return re.sub(r"[ \t]{2,}", " ", unescape(stripped)).strip()


def levenshtein(a: str, b: str, max_distance: int = 3) -> int:
    """Edit distance, short-circuiting once it provably exceeds ``max_distance``."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(
                min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb))
            )
        if min(current) > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


def skeleton(text: str) -> str:
    """Map confusable characters to their Latin look-alike for comparison.

    Also collapses the multi-character ``rn`` -> ``m`` pair, which renders almost
    identically in proportional fonts (``arnazon`` vs ``amazon``) and is one of
    the most-used typosquat tricks.
    """
    mapped = "".join(_CONFUSABLES.get(ch, ch) for ch in text.lower())
    return mapped.replace("rn", "m").replace("vv", "w")


def decode_idna(host: str) -> str:
    """Render a punycode host as Unicode so look-alike checks can see it.

    ``xn--pypal-4ve.com`` -> ``pаypal.com`` (with a Cyrillic а). Returns the input
    unchanged when it is not punycode or cannot be decoded.
    """
    if "xn--" not in host:
        return host
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
                continue
            except (UnicodeError, UnicodeDecodeError):
                pass
        labels.append(label)
    return ".".join(labels)


def looks_like_brand(host: str) -> tuple[str, str] | None:
    """Return ``(brand, reason)`` when ``host`` imitates a watched brand.

    A host that *is* the brand's own domain is not a match — only impostors are
    reported: look-alike spellings, or the brand name pushed into a subdomain or
    a hyphenated label on some unrelated registrable domain.
    """
    domain = registrable_domain(host)
    if not domain or "." not in domain:
        return None
    if domain in BRAND_DOMAINS:
        return None  # Infrastructure the brand genuinely operates.

    unicode_host = decode_idna(host)
    unicode_domain = registrable_domain(unicode_host)
    name = unicode_domain.split(".")[0]
    normalized = skeleton(name)
    was_punycode = unicode_host != host

    # Only an exact, unmodified match is the real brand. A name that merely
    # *normalizes* to the brand (paypa1 -> paypal) is the attack, not the brand.
    if name in WATCHED_BRANDS:
        return None

    for brand in WATCHED_BRANDS:
        if len(brand) < 5:
            continue
        if normalized != name and brand in normalized:
            return brand, "punycode-homograph" if was_punycode else "unicode-confusable"
        distance = levenshtein(normalized, brand, max_distance=2)
        if 0 < distance <= (1 if len(brand) <= 6 else 2):
            return brand, "typosquat"
        if brand in normalized and normalized != brand:
            return brand, "brand-in-domain"

    subdomain_part = (
        unicode_host[: -len(unicode_domain)].rstrip(".")
        if unicode_host.endswith(unicode_domain)
        else ""
    )
    if subdomain_part:
        normalized_sub = skeleton(subdomain_part)
        for brand in WATCHED_BRANDS:
            if len(brand) >= 5 and brand in normalized_sub:
                return brand, "brand-in-subdomain"
    return None


def _split_url(raw: str) -> tuple[str, str, str, int | None, str, str]:
    candidate = raw if "://" in raw else f"http://{raw}"
    try:
        parts = urlsplit(candidate)
        port = parts.port
    except ValueError:
        return "", "", "", None, "", ""
    host = (parts.hostname or "").lower()
    return parts.scheme.lower(), host, parts.netloc, port, parts.path, parts.query


def analyze_url(raw: str, anchor_text: str = "", source: str = "body") -> URLInfo:
    """Parse one URL and attach every offline forensic flag that applies."""
    raw = raw.strip().rstrip(".,;:!?)")
    info = URLInfo(url=raw, anchor_text=anchor_text.strip(), source=source)

    scheme, host, netloc, port, path, query = _split_url(raw)
    info.scheme, info.host, info.port, info.path, info.query = scheme, host, port, path, query
    info.domain = registrable_domain(host)
    info.tld = info.domain.rsplit(".", 1)[-1] if "." in info.domain else ""

    if not host:
        info.flag("unparsable")
        return info

    if scheme not in ("https", "http", "ftp", "mailto"):
        info.flag("unusual-scheme")
    if scheme == "http":
        info.flag("cleartext-http")

    if "@" in netloc:
        # Everything before '@' in the authority is userinfo — the classic trick
        # for making a hostile host look like a trusted one.
        info.flag("embedded-credentials")

    if _is_ip_host(host):
        info.flag("ip-literal-host")

    if host.startswith("xn--") or ".xn--" in host:
        info.flag("punycode-host")

    if info.domain in URL_SHORTENERS:
        info.flag("url-shortener")

    if info.tld in SUSPICIOUS_TLDS:
        info.flag("suspicious-tld")

    if port is not None and port not in (80, 443, 21):
        info.flag("nonstandard-port")

    if host.count(".") >= 4:
        info.flag("deep-subdomain")

    if any(host == h or host.endswith("." + h) for h in ABUSED_HOSTING):
        info.flag("abused-hosting")

    decoded_path = unquote(path + ("?" + query if query else ""))
    if decoded_path != (path + ("?" + query if query else "")):
        info.flag("encoded-path")

    lowered = (path + query).lower()
    if re.search(r"(?:login|signin|verify|secure|account|update|confirm|billing|password|auth|unlock|recover)", lowered):
        info.flag("credential-path")

    if re.search(r"(?i)(?:url|redirect|next|target|dest|continue|return|r|u)=https?%3a|=https?://", query):
        info.flag("open-redirect-param")

    if _EMAIL_RE.search(unquote(query)):
        info.flag("recipient-in-url")

    if brand_match := looks_like_brand(host):
        brand, reason = brand_match
        info.flag(f"brand-impersonation:{brand}:{reason}")

    if anchor_text:
        _flag_anchor_mismatch(info)

    return info


def _flag_anchor_mismatch(info: URLInfo) -> None:
    """Flag anchors whose visible text advertises a different destination."""
    text = html_to_text(info.anchor_text).strip()
    if not text:
        return

    candidates = _URL_RE.findall(text)
    if candidates:
        _, shown_host, _, _, _, _ = _split_url(candidates[0])
        shown_domain = registrable_domain(shown_host)
        if shown_domain and info.domain and shown_domain != info.domain:
            info.flag("anchor-text-mismatch")
        return

    # Bare "click here to visit paypal.com" style text.
    bare = re.match(r"^[\w.\-]+\.[a-z]{2,}$", text.strip().lower())
    if bare:
        shown_domain = registrable_domain(text.strip().lower())
        if shown_domain and info.domain and shown_domain != info.domain:
            info.flag("anchor-text-mismatch")


def _is_ip_host(host: str) -> bool:
    stripped = host.strip("[]")
    try:
        ipaddress.ip_address(stripped)
        return True
    except ValueError:
        return False


def _is_public_ip(value: str) -> bool:
    """True only for globally routable addresses.

    Internal, loopback, reserved and multicast addresses are excluded so that
    extracted IOCs are safe to feed straight into a blocklist. Note that Python
    also classifies the RFC 5737 documentation ranges (192.0.2/24, 198.51.100/24,
    203.0.113/24) as private, so those are filtered too.
    """
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def extract_iocs(parsed: ParsedEmail) -> IOCSet:
    """Collect every indicator from a parsed message."""
    iocs = IOCSet()
    seen_urls: set[str] = set()

    def add_url(info: URLInfo) -> None:
        key = info.url.lower()
        if key in seen_urls or not info.host:
            return
        seen_urls.add(key)
        iocs.urls.append(info)
        if info.domain and not _is_ip_host(info.host):
            iocs.domains.add(info.domain)
        elif _is_ip_host(info.host) and _is_public_ip(info.host.strip("[]")):
            iocs.ips.add(info.host.strip("[]"))

    # HTML anchors first: they carry the anchor text needed for mismatch checks.
    if parsed.html_body:
        for match in _HREF_RE.finditer(parsed.html_body):
            href = unescape(match.group("url")).strip()
            if href.lower().startswith(("mailto:", "tel:", "#", "javascript:")):
                if href.lower().startswith("mailto:"):
                    iocs.emails.add(href[7:].split("?", 1)[0].strip().lower())
                elif href.lower().startswith("javascript:"):
                    info = URLInfo(url=href, source="html-anchor", host="javascript")
                    info.flag("javascript-uri")
                    iocs.urls.append(info)
                continue
            add_url(analyze_url(href, anchor_text=match.group("text"), source="html-anchor"))

        for raw in _URL_RE.findall(html_to_text(parsed.html_body)):
            add_url(analyze_url(unescape(raw), source="html-text"))

    for raw in _URL_RE.findall(parsed.text_body):
        add_url(analyze_url(raw, source="text-body"))

    _collect_flat_iocs(parsed, iocs)
    return iocs


def _collect_flat_iocs(parsed: ParsedEmail, iocs: IOCSet) -> None:
    body_blob = "\n".join(
        [parsed.text_body, html_to_text(parsed.html_body), parsed.subject]
    )

    for address in _EMAIL_RE.findall(body_blob):
        iocs.emails.add(address.lower())
    for _, address in (
        parsed.from_addrs + parsed.to_addrs + parsed.cc_addrs + parsed.reply_to_addrs
    ):
        if address:
            iocs.emails.add(address.lower())
    if parsed.return_path:
        iocs.emails.add(parsed.return_path)

    for hop in parsed.received_chain:
        if hop.ip and _is_public_ip(hop.ip):
            iocs.ips.add(hop.ip)
    for candidate in _IPV4_RE.findall(body_blob):
        if _is_public_ip(candidate):
            iocs.ips.add(candidate)

    for address in iocs.emails:
        domain = registrable_domain(address.rsplit("@", 1)[-1])
        if domain:
            iocs.domains.add(domain)

    iocs.hashes["md5"].update(_MD5_RE.findall(body_blob))
    iocs.hashes["sha1"].update(_SHA1_RE.findall(body_blob))
    iocs.hashes["sha256"].update(_SHA256_RE.findall(body_blob))
    for attachment in parsed.attachments:
        iocs.hashes["sha256"].add(attachment.sha256)


def merge_iocs(sets: Iterable[IOCSet]) -> IOCSet:
    """Combine IOC sets from many messages, de-duplicating URLs by string."""
    merged = IOCSet()
    seen: set[str] = set()
    for item in sets:
        for url in item.urls:
            if url.url.lower() not in seen:
                seen.add(url.url.lower())
                merged.urls.append(url)
        merged.domains |= item.domains
        merged.ips |= item.ips
        merged.emails |= item.emails
        for algorithm, values in item.hashes.items():
            merged.hashes[algorithm] |= values
    return merged
