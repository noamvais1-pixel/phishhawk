"""Declarative phishing detection rules.

Each rule is a small pure function over ``(ParsedEmail, IOCSet)`` that returns
evidence strings when it fires. Rules carry a weight; the analyzer sums the
weights of everything that fired to produce a risk score. Keeping them
declarative means a rule can be added, re-weighted or disabled without touching
the scoring engine.

Weights are calibrated so that no single rule can push a message to CRITICAL on
its own — a verdict always needs corroboration, which keeps false positives on
legitimate bulk mail manageable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Callable

from phishhawk.iocs import IOCSet, html_to_text, looks_like_brand
from phishhawk.parser import ParsedEmail, domain_of, registrable_domain

Evidence = list[str]
CheckFn = Callable[[ParsedEmail, IOCSet], Evidence]

CATEGORY_AUTH = "authentication"
CATEGORY_IDENTITY = "sender-identity"
CATEGORY_URL = "urls"
CATEGORY_CONTENT = "content"
CATEGORY_ATTACHMENT = "attachments"
CATEGORY_HEADER = "headers"

# Extensions that can execute code, or that mail-borne malware leans on.
EXECUTABLE_EXTENSIONS = frozenset(
    {
        "exe", "scr", "com", "pif", "cpl", "msi", "msp", "bat", "cmd", "vbs",
        "vbe", "js", "jse", "wsf", "wsh", "ps1", "psm1", "hta", "jar", "reg",
        "lnk", "chm", "application", "gadget", "inf", "ins", "isp", "job",
        "msc", "mst", "sct", "shb", "vb", "ws", "dll", "iso", "img", "vhd",
    }
)

MACRO_EXTENSIONS = frozenset(
    {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "potm", "ppam", "sldm"}
)

ARCHIVE_EXTENSIONS = frozenset(
    {"zip", "rar", "7z", "gz", "tar", "bz2", "cab", "ace", "arj", "lzh", "xz", "z"}
)

# Ordered longest-first so the double-extension check reports the real type.
_DOUBLE_EXT_RE = re.compile(
    r"\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|txt|jpg|jpeg|png|gif|htm|html|csv|rtf)"
    r"\s*\.(?:exe|scr|com|pif|bat|cmd|vbs|js|jar|hta|lnk|ps1|msi|iso)$",
    re.IGNORECASE,
)

URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediate(?:ly)?\b", r"\bact now\b", r"\bexpires? (?:today|soon|in \d+)\b",
    r"\bwithin \d+ hours?\b", r"\blast (?:chance|warning|reminder)\b", r"\bfinal notice\b",
    r"\bdo not (?:ignore|delay)\b", r"\btime[- ]sensitive\b", r"\bright away\b",
    r"\bas soon as possible\b", r"\basap\b", r"\bdeadline\b", r"\bhurry\b",
]

THREAT_PATTERNS = [
    r"\b(?:account|access|service) (?:will be |has been |is )?(?:suspend|terminat|deactivat|clos|disabl|lock|restrict)",
    r"\bunauthori[sz]ed (?:access|login|attempt|activity|transaction)\b",
    r"\bunusual (?:activity|sign[- ]?in|login)\b", r"\bsecurity (?:alert|breach|violation)\b",
    r"\bpermanent(?:ly)? (?:delet|remov|clos|lost)\b", r"\blegal action\b",
    r"\bfailure to (?:comply|respond|verify|act)\b", r"\byour account (?:is|was|has been)\b",
    r"\bpayment (?:failed|declined|overdue)\b", r"\bavoid (?:suspension|interruption|closure)\b",
]

CREDENTIAL_PATTERNS = [
    r"\b(?:verify|confirm|validate|update|re[- ]?enter|re[- ]?activate) your (?:account|identity|password|credentials|details|information|billing|payment)\b",
    r"\bsign in (?:here|now|to (?:continue|verify|confirm))\b",
    r"\b(?:click|tap|press) (?:here|below|the (?:link|button))\b",
    r"\benter your (?:password|credentials|pin|username|login)\b",
    r"\blog ?in to (?:your account|verify|confirm|restore)\b",
    r"\bunlock your account\b", r"\brestore (?:access|your account)\b",
    r"\breset your password\b", r"\bconfirm your email\b",
]

FINANCIAL_PATTERNS = [
    r"\bwire transfer\b", r"\bbank (?:details|account|transfer)\b", r"\bgift ?cards?\b",
    r"\bbitcoin\b", r"\bcrypto(?:currency)?\b", r"\bwallet address\b", r"\bbeneficiary\b",
    r"\binvoice attached\b", r"\bpayment (?:instructions?|details)\b", r"\bremittance\b",
    r"\bchange (?:of )?bank\b", r"\bupdated? (?:banking|payment) (?:details|information)\b",
    r"\bpurchase (?:some )?gift ?cards?\b", r"\bwestern union\b", r"\bmoneygram\b",
]

# BEC pretexts: short, text-only, no links, sent from a display name that matches
# an executive. The wording is deliberately mundane, which is what defeats
# keyword-only filters.
BEC_PATTERNS = [
    r"\bare you (?:available|at your desk|free|around|in the office)\b",
    r"\bi need (?:a |your )?(?:favor|help|quick|urgent)\b",
    r"\bi'?m (?:currently )?(?:in a meeting|busy|travel|tied up|unavailable)\b",
    r"\bcan you (?:handle|do|take care of) (?:this|something) for me\b",
    r"\bsent from my (?:iphone|ipad|mobile)\b",
    r"\bdiscreet(?:ly)?\b", r"\bkeep this (?:between us|confidential|private)\b",
    r"\bwhat'?s your (?:availability|cell|mobile)\b",
]

_EXEC_TITLES = re.compile(
    r"(?i)\b(?:ceo|cfo|coo|cto|president|director|vp|vice president|chairman|"
    r"managing director|head of|chief)\b"
)

_LOOKALIKE_FREEMAIL = frozenset(
    {
        "gmail.com", "googlemail.com", "yahoo.com", "hotmail.com", "outlook.com",
        "aol.com", "protonmail.com", "proton.me", "mail.com", "gmx.com",
        "yandex.com", "zoho.com", "icloud.com", "live.com", "msn.com",
        "inbox.lv", "tutanota.com", "mail.ru", "rambler.ru",
    }
)


@dataclass
class Rule:
    """One detection heuristic."""

    id: str
    name: str
    weight: int
    category: str
    description: str
    check: CheckFn
    mitre: str = ""

    def run(self, parsed: ParsedEmail, iocs: IOCSet) -> "Finding | None":
        try:
            evidence = self.check(parsed, iocs)
        except Exception as exc:  # A broken rule must not abort the whole scan.
            return Finding(
                rule_id=self.id,
                name=self.name,
                weight=0,
                category=self.category,
                description=self.description,
                evidence=[f"rule error: {exc}"],
                mitre=self.mitre,
                errored=True,
            )
        if not evidence:
            return None
        return Finding(
            rule_id=self.id,
            name=self.name,
            weight=self.weight,
            category=self.category,
            description=self.description,
            evidence=evidence,
            mitre=self.mitre,
        )


@dataclass
class Finding:
    """A rule that fired, with the evidence that made it fire."""

    rule_id: str
    name: str
    weight: int
    category: str
    description: str
    evidence: Evidence = field(default_factory=list)
    mitre: str = ""
    errored: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "weight": self.weight,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "mitre": self.mitre,
        }


def _visible_text(parsed: ParsedEmail) -> str:
    return f"{parsed.subject}\n{parsed.text_body}\n{html_to_text(parsed.html_body)}"


def _match_patterns(text: str, patterns: list[str], limit: int = 4) -> list[str]:
    hits: list[str] = []
    lowered = text.lower()
    for pattern in patterns:
        match = re.search(pattern, lowered, re.IGNORECASE)
        if match:
            snippet = match.group(0).strip()
            if snippet and snippet not in hits:
                hits.append(snippet)
        if len(hits) >= limit:
            break
    return hits


# --------------------------------------------------------------------------- #
# Authentication rules
# --------------------------------------------------------------------------- #


def _check_spf_fail(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    verdict = parsed.auth_results.get("spf", "")
    if verdict in ("fail", "softfail", "permerror"):
        return [f"SPF={verdict}"]
    return []


def _check_dkim_fail(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    verdict = parsed.auth_results.get("dkim", "")
    if verdict in ("fail", "permerror", "policy"):
        return [f"DKIM={verdict}"]
    return []


def _check_dmarc_fail(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    verdict = parsed.auth_results.get("dmarc", "")
    if verdict in ("fail", "permerror"):
        return [f"DMARC={verdict}"]
    return []


def _check_no_auth(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    if not parsed.auth_results and not parsed.has_header("Authentication-Results"):
        return ["no Authentication-Results or Received-SPF header present"]
    return []


# --------------------------------------------------------------------------- #
# Sender-identity rules
# --------------------------------------------------------------------------- #


def _check_reply_to_mismatch(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    if not parsed.reply_to_addrs or not parsed.from_address:
        return []
    from_domain = registrable_domain(parsed.from_domain)
    hits = []
    for _, address in parsed.reply_to_addrs:
        reply_domain = registrable_domain(domain_of(address))
        if reply_domain and from_domain and reply_domain != from_domain:
            hits.append(f"From={parsed.from_address} but Reply-To={address}")
    return hits


def _check_return_path_mismatch(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    if not parsed.return_path or not parsed.from_address:
        return []
    envelope = registrable_domain(domain_of(parsed.return_path))
    header = registrable_domain(parsed.from_domain)
    if envelope and header and envelope != header:
        return [f"envelope sender {parsed.return_path} vs header From {parsed.from_address}"]
    return []


def _check_display_name_spoof(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    name = parsed.from_display_name
    address = parsed.from_address
    if not name or not address:
        return []
    hits = []

    # Display name that is itself an address pointing somewhere else.
    embedded = re.search(r"[\w.\-+]+@[\w.\-]+\.\w{2,}", name)
    if embedded:
        shown = embedded.group(0).lower()
        if registrable_domain(domain_of(shown)) != registrable_domain(parsed.from_domain):
            hits.append(f'display name shows "{shown}" but real sender is {address}')

    # Display name claims a brand the sending domain has no relationship with.
    normalized = re.sub(r"[^a-z0-9]", "", name.lower())
    sending_domain = registrable_domain(parsed.from_domain)
    domain_root = sending_domain.split(".")[0] if sending_domain else ""
    for brand in ("microsoft", "office365", "paypal", "amazon", "apple", "google",
                  "netflix", "docusign", "dropbox", "linkedin", "facebook", "chase",
                  "coinbase", "binance", "fedex", "dhl", "adobe", "zoom"):
        if brand in normalized and brand not in domain_root:
            hits.append(f'display name claims "{name}" but sender domain is {sending_domain}')
            break
    return hits


def _check_lookalike_sender_domain(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    if not parsed.from_domain:
        return []
    match = looks_like_brand(parsed.from_domain)
    if match:
        brand, reason = match
        return [f"sender domain {parsed.from_domain} resembles {brand} ({reason})"]
    return []


def _check_exec_freemail(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    """Executive display name sent from a free consumer mailbox — classic BEC."""
    name = parsed.from_display_name
    domain = registrable_domain(parsed.from_domain)
    if not name or domain not in _LOOKALIKE_FREEMAIL:
        return []
    if _EXEC_TITLES.search(name) or _EXEC_TITLES.search(parsed.subject):
        return [f'"{name}" <{parsed.from_address}> uses a free mail provider']
    # A two-word human name from freemail combined with BEC phrasing.
    if len(name.split()) >= 2 and _match_patterns(_visible_text(parsed), BEC_PATTERNS, limit=1):
        return [f'"{name}" <{parsed.from_address}> — personal-name freemail with BEC phrasing']
    return []


# --------------------------------------------------------------------------- #
# URL rules
# --------------------------------------------------------------------------- #


def _url_flag_rule(flag_prefix: str, label: str) -> CheckFn:
    def check(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
        hits = []
        for url in iocs.urls:
            if any(f.startswith(flag_prefix) for f in url.flags):
                hits.append(f"{label}: {url.url[:160]}")
            if len(hits) >= 5:
                break
        return hits

    return check


def _check_brand_impersonating_url(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    hits = []
    for url in iocs.urls:
        for flag in url.flags:
            if flag.startswith("brand-impersonation:"):
                _, brand, reason = flag.split(":", 2)
                hits.append(f"{url.host} imitates {brand} ({reason})")
        if len(hits) >= 5:
            break
    return hits


def _check_url_domain_diversity(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    """Link domain unrelated to the sender — normal for bulk mail, notable with other signals."""
    sender = registrable_domain(parsed.from_domain)
    if not sender or not iocs.urls:
        return []
    unrelated = {
        u.domain
        for u in iocs.urls
        if u.domain and u.domain != sender and u.source in ("html-anchor", "text-body")
    }
    if len(unrelated) >= 4:
        return [f"{len(unrelated)} link domains none of which match sender {sender}: "
                + ", ".join(sorted(unrelated)[:6])]
    return []


# --------------------------------------------------------------------------- #
# Content rules
# --------------------------------------------------------------------------- #


def _content_rule(patterns: list[str], label: str) -> CheckFn:
    def check(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
        hits = _match_patterns(_visible_text(parsed), patterns)
        return [f'{label}: "{h}"' for h in hits]

    return check


def _check_credential_form(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    """An HTML form posting off-domain, or any password input, inside an email."""
    html = parsed.html_body
    if not html:
        return []
    hits = []
    if re.search(r'(?i)<input[^>]+type\s*=\s*["\']?password', html):
        hits.append("HTML body contains a password input field")
    for match in re.finditer(r'(?i)<form\b[^>]*?action\s*=\s*["\']?([^"\'\s>]+)', html):
        action = match.group(1)
        if action.lower().startswith(("http://", "https://")):
            hits.append(f"HTML form posts to external URL: {action[:120]}")
        else:
            hits.append("HTML body contains a form")
    return hits[:4]


def _check_hidden_text(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    """Invisible text used to dilute keyword-based filters."""
    html = parsed.html_body
    if not html:
        return []
    hits = []
    if re.search(r"(?i)(?:font-size\s*:\s*0(?:px|pt|em)?|display\s*:\s*none|visibility\s*:\s*hidden)", html):
        hits.append("CSS hides body content (font-size:0 / display:none / visibility:hidden)")
    if re.search(r"(?i)color\s*:\s*#?(?:fff(?:fff)?|white)\b[^;]*", html) and re.search(
        r"(?i)background(?:-color)?\s*:\s*#?(?:fff(?:fff)?|white)\b", html
    ):
        hits.append("white-on-white text detected")
    if re.search(r"[​‌‍⁠﻿]{3,}", html):
        hits.append("repeated zero-width characters embedded in body")
    return hits


def _check_image_only_body(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    """Body carried entirely in an image so text scanners have nothing to read."""
    text = html_to_text(parsed.html_body) + parsed.text_body
    if not parsed.html_body:
        return []
    images = len(re.findall(r"(?i)<img\b", parsed.html_body))
    if images >= 1 and len(text.strip()) < 120 and iocs.urls:
        return [f"body is {len(text.strip())} chars of text with {images} image(s) and {len(iocs.urls)} link(s)"]
    return []


def _check_generic_greeting(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    patterns = [
        r"\bdear (?:customer|user|client|member|account holder|sir/madam|sir or madam|valued customer)\b",
        r"^\s*dear (?:friend|winner)\b",
        r"\bhello dear\b", r"\battention:? (?:customer|user|account holder)\b",
    ]
    hits = _match_patterns(_visible_text(parsed), patterns, limit=2)
    return [f'generic greeting: "{h}"' for h in hits]


def _check_reply_prefix_no_thread(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    """``Re:`` / ``Fwd:`` subject with no References or In-Reply-To — faked thread."""
    if not re.match(r"(?i)^\s*(?:re|fw|fwd|aw|antw|sv)\s*[:\]]", parsed.subject):
        return []
    if parsed.has_header("In-Reply-To") or parsed.has_header("References"):
        return []
    return [f'subject "{parsed.subject[:80]}" implies a thread but no In-Reply-To/References header']


def _check_bec_pretext(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    hits = _match_patterns(_visible_text(parsed), BEC_PATTERNS, limit=3)
    if not hits:
        return []
    # Strongest when the message is short and link-free — the classic BEC opener.
    body_length = len(_visible_text(parsed).strip())
    context = " (short, link-free message)" if body_length < 600 and not iocs.urls else ""
    return [f'BEC pretext{context}: "{h}"' for h in hits]


# --------------------------------------------------------------------------- #
# Attachment rules
# --------------------------------------------------------------------------- #


def _check_executable_attachment(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    return [
        f"{a.filename} ({a.content_type}, {a.size} bytes)"
        for a in parsed.attachments
        if a.extension in EXECUTABLE_EXTENSIONS
    ][:5]


def _check_macro_attachment(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    return [
        f"macro-enabled document: {a.filename}"
        for a in parsed.attachments
        if a.extension in MACRO_EXTENSIONS
    ][:5]


def _check_double_extension(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    hits = []
    for attachment in parsed.attachments:
        name = attachment.filename
        if _DOUBLE_EXT_RE.search(name):
            hits.append(f"double extension: {name}")
        # Right-to-left override reverses how the name renders in the mail client.
        if "‮" in name or "‫" in name:
            hits.append(f"right-to-left override character in filename: {name!r}")
    return hits[:5]


def _check_archive_attachment(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    return [
        f"archive attachment: {a.filename} ({a.size} bytes)"
        for a in parsed.attachments
        if a.extension in ARCHIVE_EXTENSIONS
    ][:5]


def _check_html_attachment(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    """HTML/SVG attachments are a common way to smuggle a phishing page past filters."""
    return [
        f"markup attachment (possible HTML smuggling): {a.filename}"
        for a in parsed.attachments
        if a.extension in ("html", "htm", "shtml", "svg", "xhtml", "mhtml", "mht")
    ][:5]


# --------------------------------------------------------------------------- #
# Header / routing rules
# --------------------------------------------------------------------------- #


def _check_suspicious_mailer(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    mailer = parsed.header("X-Mailer") + " " + parsed.header("User-Agent")
    suspicious = ["phpmailer", "swiftmailer", "python", "sendmail-", "mass", "bulk",
                  "the bat", "foxmail", "aspnetmailer", "smtplib"]
    lowered = mailer.lower()
    hits = [f"X-Mailer/User-Agent: {mailer.strip()[:100]}" for s in suspicious if s in lowered]
    return hits[:1]


def _check_missing_message_id(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    if not parsed.message_id:
        return ["message has no Message-ID header"]
    if not re.match(r"^<[^>]+@[^>]+>$", parsed.message_id.strip()):
        return [f"malformed Message-ID: {parsed.message_id[:80]}"]
    domain = registrable_domain(parsed.message_id.strip("<>").rsplit("@", 1)[-1].strip(">"))
    sender = registrable_domain(parsed.from_domain)
    if domain and sender and domain != sender and parsed.auth_results.get("dkim") != "pass":
        return [f"Message-ID domain {domain} does not match sender {sender}"]
    return []


def _check_date_anomaly(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    """Header Date far from the earliest Received timestamp — forged or replayed."""
    if not parsed.date or not parsed.received_chain:
        return []
    stamps = [h.timestamp for h in parsed.received_chain if h.timestamp]
    if not stamps:
        return []
    delta = min(stamps) - parsed.date
    if abs(delta) > timedelta(hours=24):
        hours = int(abs(delta).total_seconds() // 3600)
        return [f"Date header differs from first Received timestamp by {hours}h"]
    return []


def _check_recipient_not_addressed(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    """No To/Cc at all, or an undisclosed-recipients placeholder — bulk blast."""
    if not parsed.to_addrs and not parsed.cc_addrs:
        return ["message has no To or Cc recipients (likely BCC blast)"]
    for name, address in parsed.to_addrs:
        if "undisclosed" in (name + address).lower():
            return [f"recipients hidden: {name or address}"]
    return []


def _check_bulk_headers(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    """Marketing headers present — used to *lower* suspicion, reported for context."""
    markers = [
        h for h in ("List-Unsubscribe", "List-Id", "Precedence", "Feedback-ID",
                    "X-Campaign-Id", "List-Unsubscribe-Post")
        if parsed.has_header(h)
    ]
    return [f"bulk-mail headers present: {', '.join(markers)}"] if markers else []


ALL_RULES: list[Rule] = [
    # -- authentication ------------------------------------------------------
    Rule("AUTH001", "SPF failure", 18, CATEGORY_AUTH,
         "The sending IP is not authorized to send for the envelope domain.",
         _check_spf_fail, mitre="T1566.002"),
    Rule("AUTH002", "DKIM failure", 15, CATEGORY_AUTH,
         "The message signature is missing or does not validate.",
         _check_dkim_fail, mitre="T1566.002"),
    Rule("AUTH003", "DMARC failure", 22, CATEGORY_AUTH,
         "The message fails the sender domain's published DMARC alignment policy.",
         _check_dmarc_fail, mitre="T1566.002"),
    Rule("AUTH004", "No authentication results", 8, CATEGORY_AUTH,
         "No receiving MTA recorded SPF/DKIM/DMARC results for this message.",
         _check_no_auth),

    # -- sender identity -----------------------------------------------------
    Rule("SEND001", "Reply-To domain differs from From", 16, CATEGORY_IDENTITY,
         "Replies are routed to a different domain than the apparent sender.",
         _check_reply_to_mismatch, mitre="T1534"),
    Rule("SEND002", "Envelope sender differs from header From", 12, CATEGORY_IDENTITY,
         "Return-Path and From disagree, a common trait of spoofed mail.",
         _check_return_path_mismatch, mitre="T1566.002"),
    Rule("SEND003", "Display-name spoofing", 20, CATEGORY_IDENTITY,
         "The friendly name impersonates a brand or address unrelated to the sender.",
         _check_display_name_spoof, mitre="T1656"),
    Rule("SEND004", "Look-alike sender domain", 26, CATEGORY_IDENTITY,
         "The sending domain typosquats or otherwise imitates a known brand.",
         _check_lookalike_sender_domain, mitre="T1583.001"),
    Rule("SEND005", "Executive identity from free mail provider", 22, CATEGORY_IDENTITY,
         "A named executive or BEC pretext arriving from a consumer mailbox.",
         _check_exec_freemail, mitre="T1534"),

    # -- urls ----------------------------------------------------------------
    Rule("URL001", "Anchor text does not match destination", 24, CATEGORY_URL,
         "The visible link text advertises a different site than the href.",
         _url_flag_rule("anchor-text-mismatch", "link text/destination mismatch"),
         mitre="T1566.002"),
    Rule("URL002", "Credentials embedded in URL authority", 26, CATEGORY_URL,
         "A user@host URL disguises the true destination host.",
         _url_flag_rule("embedded-credentials", "userinfo in URL"), mitre="T1566.002"),
    Rule("URL003", "Link points at a bare IP address", 20, CATEGORY_URL,
         "Legitimate services publish hostnames; raw IPs evade reputation checks.",
         _url_flag_rule("ip-literal-host", "IP-literal link")),
    Rule("URL004", "Punycode host", 22, CATEGORY_URL,
         "An internationalized hostname that can render as a Latin look-alike.",
         _url_flag_rule("punycode-host", "punycode host")),
    Rule("URL005", "Brand-impersonating link host", 25, CATEGORY_URL,
         "A link host typosquats or embeds a well-known brand name.",
         _check_brand_impersonating_url, mitre="T1583.001"),
    Rule("URL006", "URL shortener", 10, CATEGORY_URL,
         "The real destination is hidden behind a redirect service.",
         _url_flag_rule("url-shortener", "shortened link"), mitre="T1566.002"),
    Rule("URL007", "Open-redirect parameter", 14, CATEGORY_URL,
         "A trusted host is used to bounce the victim to an attacker URL.",
         _url_flag_rule("open-redirect-param", "redirect parameter")),
    Rule("URL008", "Credential-themed link path", 12, CATEGORY_URL,
         "The link path advertises login, verification or account recovery.",
         _url_flag_rule("credential-path", "credential-themed path"), mitre="T1566.002"),
    Rule("URL009", "Low-reputation TLD", 8, CATEGORY_URL,
         "The link uses a TLD heavily abused for disposable phishing infrastructure.",
         _url_flag_rule("suspicious-tld", "low-reputation TLD")),
    Rule("URL010", "Recipient address embedded in link", 12, CATEGORY_URL,
         "The victim's address is pre-filled, a hallmark of targeted credential pages.",
         _url_flag_rule("recipient-in-url", "recipient address in URL")),
    Rule("URL011", "Free hosting or file-sharing landing page", 12, CATEGORY_URL,
         "Credential pages are frequently hosted on trusted free platforms.",
         _url_flag_rule("abused-hosting", "abused hosting platform")),
    Rule("URL012", "javascript: URI in body", 18, CATEGORY_URL,
         "Script URIs in mail bodies are used to build content in the client.",
         _url_flag_rule("javascript-uri", "script URI")),
    Rule("URL013", "Non-standard port", 10, CATEGORY_URL,
         "Legitimate web services rarely serve mail links on unusual ports.",
         _url_flag_rule("nonstandard-port", "non-standard port")),
    Rule("URL014", "Many unrelated link domains", 8, CATEGORY_URL,
         "The message links to several domains unrelated to the sender.",
         _check_url_domain_diversity),

    # -- content -------------------------------------------------------------
    Rule("CONT001", "Urgency pressure", 10, CATEGORY_CONTENT,
         "Time pressure discourages the recipient from verifying the request.",
         _content_rule(URGENCY_PATTERNS, "urgency"), mitre="T1566"),
    Rule("CONT002", "Consequence or threat language", 14, CATEGORY_CONTENT,
         "Threatened suspension, loss or legal action to force compliance.",
         _content_rule(THREAT_PATTERNS, "threat"), mitre="T1566"),
    Rule("CONT003", "Credential-harvesting call to action", 18, CATEGORY_CONTENT,
         "The message asks the recipient to verify, confirm or re-enter credentials.",
         _content_rule(CREDENTIAL_PATTERNS, "credential request"), mitre="T1566.002"),
    Rule("CONT004", "Financial or payment-redirection language", 16, CATEGORY_CONTENT,
         "Wire, gift-card, crypto or bank-detail change requests.",
         _content_rule(FINANCIAL_PATTERNS, "financial"), mitre="T1657"),
    Rule("CONT005", "Credential form in HTML body", 26, CATEGORY_CONTENT,
         "The email itself contains a form or password field posting off-domain.",
         _check_credential_form, mitre="T1566.002"),
    Rule("CONT006", "Hidden or obfuscated text", 16, CATEGORY_CONTENT,
         "Invisible content used to dilute keyword-based filtering.",
         _check_hidden_text, mitre="T1027"),
    Rule("CONT007", "Image-only body", 12, CATEGORY_CONTENT,
         "Text is rendered inside an image so scanners have nothing to read.",
         _check_image_only_body, mitre="T1027"),
    Rule("CONT008", "Generic greeting", 6, CATEGORY_CONTENT,
         "Impersonal salutation typical of untargeted bulk phishing.",
         _check_generic_greeting),
    Rule("CONT009", "Fabricated reply thread", 12, CATEGORY_CONTENT,
         "A Re:/Fwd: subject with no threading headers fakes prior correspondence.",
         _check_reply_prefix_no_thread, mitre="T1566"),
    Rule("CONT010", "Business-email-compromise pretext", 18, CATEGORY_CONTENT,
         "Conversational opener designed to start a payment-fraud exchange.",
         _check_bec_pretext, mitre="T1534"),

    # -- attachments ---------------------------------------------------------
    Rule("ATT001", "Executable attachment", 30, CATEGORY_ATTACHMENT,
         "The message carries a directly runnable file.",
         _check_executable_attachment, mitre="T1566.001"),
    Rule("ATT002", "Macro-enabled document", 24, CATEGORY_ATTACHMENT,
         "Office document capable of executing VBA on open.",
         _check_macro_attachment, mitre="T1566.001"),
    Rule("ATT003", "Deceptive filename", 28, CATEGORY_ATTACHMENT,
         "Double extension or RTL override hides the real file type.",
         _check_double_extension, mitre="T1036.007"),
    Rule("ATT004", "Archive attachment", 10, CATEGORY_ATTACHMENT,
         "Archives conceal payload contents from mail-gateway scanners.",
         _check_archive_attachment, mitre="T1566.001"),
    Rule("ATT005", "HTML or SVG attachment", 20, CATEGORY_ATTACHMENT,
         "Markup attachments are used to smuggle phishing pages past filters.",
         _check_html_attachment, mitre="T1566.001"),

    # -- headers -------------------------------------------------------------
    Rule("HDR001", "Bulk or scripted mailer", 8, CATEGORY_HEADER,
         "Sending software commonly used by mass-mail and phishing kits.",
         _check_suspicious_mailer),
    Rule("HDR002", "Missing or inconsistent Message-ID", 10, CATEGORY_HEADER,
         "Absent, malformed, or off-domain Message-ID without a valid signature.",
         _check_missing_message_id),
    Rule("HDR003", "Date inconsistent with delivery chain", 12, CATEGORY_HEADER,
         "The claimed send time disagrees with the earliest relay timestamp.",
         _check_date_anomaly),
    Rule("HDR004", "Recipient not directly addressed", 6, CATEGORY_HEADER,
         "No To/Cc recipients, indicating a blind-carbon blast.",
         _check_recipient_not_addressed),
]

# Informational: never contributes to the score, but shown as context because
# genuine marketing mail trips several content rules and this explains why.
CONTEXT_RULES: list[Rule] = [
    Rule("INFO001", "Legitimate bulk-mail headers", 0, CATEGORY_HEADER,
         "List-Unsubscribe/List-Id present, typical of real marketing mail.",
         _check_bulk_headers),
]


def rules_by_id() -> dict[str, Rule]:
    return {rule.id: rule for rule in ALL_RULES + CONTEXT_RULES}
