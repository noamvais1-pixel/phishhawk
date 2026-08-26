# 🦅 PhishHawk

**Offline phishing email triage and forensics.** Point it at a suspicious `.eml`
file — or a folder of hundreds — and get an explainable risk verdict, the
evidence behind it, and a defanged indicator list you can paste straight into a
ticket or a blocklist.

Pure Python standard library. **No dependencies, no installation, no network
calls.** Nothing you analyze ever leaves your machine — which matters, because
the messages you triage contain your colleagues' names, addresses and business.

```bash
python3 -m phishhawk triage ~/suspicious-mail/
```

```
VERDICT     SCORE  FILE                          FROM                            SUBJECT
────────────────────────────────────────────────────────────────────────────────────────────────
CRITICAL      100  01_credential_phish_m365.eml  no-reply@micros0ft-support.com  Action required: unusual sign-in activity
CRITICAL      100  03_malware_invoice.eml        billing@invoice-dispatch.click  Fwd: Outstanding invoice INV-88213
CRITICAL      100  06_homograph_paypal.eml       alerts@xn--pypal-4ve.com        Your account has been limited
HIGH           66  02_bec_ceo_wire_fraud.eml     danielroth.ceo88@gmail.com      Re: Quick request
BENIGN          6  05_legitimate_newsletter.eml  deals@retailer-example.com      Last chance! Summer sale ends today
BENIGN          0  04_legitimate_github.eml      notifications@github.com        [example/repo] Pull request #142 was merged

summary  CRITICAL=3  HIGH=1  BENIGN=2   total=6
```

---

## Why this exists

Most mail-security tooling either lives inside a gateway you can't query, or
ships message content to a third-party API. When someone forwards you a
suspicious email and asks *"is this real?"*, you usually end up reading raw
headers by hand.

PhishHawk does that reading for you, and — this is the part that matters — it
**shows its work**. Every point in the score is attributable to a named rule
with the evidence that triggered it, so you can disagree with the tool
intelligently instead of trusting a black-box number.

### It catches what SPF/DKIM/DMARC cannot

Authentication checks answer *"was this really sent by the domain it claims?"*
They are useless against business email compromise, where the attacker sends
from a **real** mailbox they genuinely control:

```
 HIGH  score 66/100
from        "Daniel Roth | CEO" <danielroth.ceo88@gmail.com>
reply-to    d.roth.finance@outlook.com
auth        DKIM=pass  DMARC=pass  SPF=pass      ← every check passes

── FINDINGS ──────────────────────────────────────────────────────────
  [22] SEND005 Executive identity from free mail provider (T1534)
       · "Daniel Roth | CEO" <danielroth.ceo88@gmail.com> uses a free mail provider
  [18] CONT010 Business-email-compromise pretext (T1534)
       · BEC pretext (short, link-free message): "are you available"
       · BEC pretext (short, link-free message): "i'm currently in a meeting"
  [16] SEND001 Reply-To domain differs from From (T1534)
       · From=danielroth.ceo88@gmail.com but Reply-To=d.roth.finance@outlook.com
  [16] CONT004 Financial or payment-redirection language (T1657)
       · financial: "wire transfer"
       · financial: "updated payment details"
  [12] CONT009 Fabricated reply thread (T1566)
       · subject "Re: Quick request" implies a thread but no In-Reply-To/References header
```

A perfectly authenticated Gmail message, correctly flagged as wire fraud.

---

## Install

There is nothing to install. Clone it and run it:

```bash
git clone https://github.com/noamvais1-pixel/phishhawk.git
cd phishhawk
python3 -m phishhawk --help
```

Requires **Python 3.10 or newer** and nothing else.

Optionally put it on your `PATH`:

```bash
pip install -e .
phishhawk triage ~/mail/
```

---

## Usage

### `triage` — batch-score a folder, worst first

The daily driver. Scores every message and sorts by risk.

```bash
python3 -m phishhawk triage ~/reported-phish/ -r
python3 -m phishhawk triage ~/mail/ --verdict SUSPICIOUS      # hide the noise
python3 -m phishhawk triage ~/mail/ -f html -o report.html    # shareable report
python3 -m phishhawk triage ~/mail/ -f csv  -o triage.csv     # for a spreadsheet
```

Reads `.eml` files, whole directories, and **mbox archives** (auto-detected and
unpacked into individual messages).

### `scan` — deep report on one message

```bash
python3 -m phishhawk scan suspicious.eml           # full terminal report
python3 -m phishhawk scan suspicious.eml -v        # + rule descriptions, all IOCs
python3 -m phishhawk scan suspicious.eml -f markdown -o ticket.md
python3 -m phishhawk scan suspicious.eml -f json | jq '.results[0].verdict'
```

### `iocs` — paste-ready indicator list

Defanged by default, so nothing in your ticket is clickable by accident.

```bash
python3 -m phishhawk iocs ~/campaign/ 
```

```
# urls (11)
hxxps[://]login[.]microsoftonline[.]com[.]verify-session[.]top/auth?u=finance[at]example[.]com
hxxps[://]accounts-paypal[.]firebaseapp[.]com/secure/update
...
# domains (15)
verify-session[.]top
secure-mail-verify[.]xyz
```

Use `--fanged` to emit live indicators for machine ingestion into a blocklist.

### `headers` — read the delivery chain

```bash
python3 -m phishhawk headers suspicious.eml
python3 -m phishhawk headers suspicious.eml --all   # dump every header
```

```
authentication
  DKIM     none
  DMARC    fail
  SPF      fail

delivery chain (origin first)
  [0] win-kj3d9a → mail-delivery-svc.top
      ip=127.0.0.1  proto=SMTP  2025-08-12 03:14:18 -0700
  [1] mail-delivery-svc.top → mx.example.com
      ip=45.132.19.204  proto=ESMTP  2025-08-12 03:14:22 -0700
```

### `rules` — see exactly what it looks for

```bash
python3 -m phishhawk rules
python3 -m phishhawk rules --category attachments
python3 -m phishhawk rules -f markdown        # paste into your own docs
```

---

## What it detects

**43 weighted rules** across six categories, each mapped to MITRE ATT&CK where
one applies.

| Category | Examples |
| --- | --- |
| **Authentication** | SPF / DKIM / DMARC failures, missing `Authentication-Results` |
| **Sender identity** | Look-alike domains, display-name spoofing, `Reply-To` divergence, envelope mismatch, executives on free mail |
| **URLs** | Anchor-text vs. destination mismatch, `user@host` credential tricks, punycode homographs, IP-literal links, open redirects, shorteners, abused free hosting |
| **Content** | Credential forms embedded in the body, urgency and threat language, BEC pretexts, hidden white-on-white text, fabricated reply threads |
| **Attachments** | Executables, macro-enabled Office documents, double extensions, right-to-left override filenames, HTML smuggling |
| **Headers** | Scripted mailers, inconsistent `Message-ID`, `Date` disagreeing with the delivery chain |

### Look-alike domain detection

Handles the tricks that plain string comparison misses:

| Domain | Detected as |
| --- | --- |
| `micros0ft-support.com` | `microsoft` — digit-for-letter confusable |
| `xn--pypal-4ve.com` | `paypal` — punycode homograph (decodes to `pаypal.com`, Cyrillic `а`) |
| `arnazon.com` | `amazon` — `rn` renders as `m` |
| `netfIix.com` | `netflix` — capital `I` for lowercase `l` |
| `secure-paypal-login.xyz` | `paypal` — brand name on an unrelated registrable domain |
| `accounts-paypal.firebaseapp.com` | `paypal` — brand pushed into a subdomain |
| `login.microsoftonline.com` | **not flagged** — genuine Microsoft infrastructure |

That last row is the hard part. An allowlist of real brand infrastructure keeps
authentic notifications from being flagged, which is what makes the rule usable
in production rather than merely clever.

---

## How scoring works

The score is a **sum of the weights of the rules that fired**, with two
adjustments that keep real-world mail out of trouble:

**Per-category caps.** Ten URL rules firing says roughly the same thing as three
firing, so each category's contribution is capped. Without this, a message with
many links outranks a message with a forged sender.

**Mitigations.** Full SPF/DKIM/DMARC alignment and genuine bulk-mail headers
subtract from the total. A newsletter that trips *urgency* and *generic
greeting* should not land beside a spoofed invoice.

```
── SCORING ───────────────────────────────────────────────────────────
  +authentication: 34 (capped from 40, 2 rules)
  +content: 42 (capped from 90, 6 rules)
  +headers: 18 (2 rules)
  +sender-identity: 38 (capped from 74, 4 rules)
  +urls: 46 (capped from 81, 5 rules)
  = 100/100 → CRITICAL
```

| Score | Verdict | Meaning |
| ---: | --- | --- |
| 80–100 | `CRITICAL` | Multiple strong signals. Quarantine and hunt for other copies. |
| 60–79 | `HIGH` | Very likely malicious. Contain and investigate. |
| 35–59 | `SUSPICIOUS` | Needs a human. Verify through a known-good channel. |
| 15–34 | `LOW` | Probably fine. Keep the indicators for correlation. |
| 0–14 | `BENIGN` | Nothing meaningful fired. |

No single rule can reach `CRITICAL` alone — a verdict always needs
corroboration. Conversely, a small set of **hard signals** (executable
attachment, deceptive filename, embedded-credential URL, credential form,
look-alike sender) can never be scored down to `BENIGN`, no matter how many
mitigations apply.

Disagree with a rule? Turn it off:

```bash
python3 -m phishhawk triage ~/mail/ --disable CONT001,URL009
```

---

## Automation

Exit codes make it usable in a pipeline:

| Code | Meaning |
| ---: | --- |
| `0` | Nothing reached the threshold |
| `1` | At least one message reached it (default: `SUSPICIOUS`) |
| `2` | Error |
| `3` | No messages to analyze |

The detection commands — `scan`, `triage` and `iocs` — use code `1` to report
findings. The inspection commands — `headers` and `rules` — only render what is
there and always exit `0`, so they are safe under `set -e`.

```bash
# Gate a mail-drop directory in CI
python3 -m phishhawk triage ./incoming/ --fail-on HIGH --no-color || \
  echo "malicious mail detected" >&2
```

Filters change what is *displayed*; the exit code always reflects the worst
message actually analyzed.

```bash
# Nightly IOC feed for your blocklist
python3 -m phishhawk iocs ~/quarantine/ -r --fanged -o /var/feeds/phish-iocs.txt

# JSON into your SIEM
python3 -m phishhawk triage ~/quarantine/ -f json | \
  jq -c '.results[] | select(.score >= 60) | {verdict, score, from: .email.from[0].address}'
```

---

## Library use

Every layer is importable:

```python
from phishhawk import parse_file, analyze

analysis = analyze(parse_file("suspicious.eml"), source="suspicious.eml")

print(analysis.verdict, analysis.score)          # CRITICAL 100
print(analysis.mitre_techniques)                 # ['T1027', 'T1534', ...]

for finding in analysis.top_findings:
    print(finding.rule_id, finding.name, finding.evidence)

for url in analysis.iocs.urls:
    if url.flags:
        print(url.url, url.flags)

analysis.to_dict()                               # fully JSON-serializable
```

Adding a rule is a function and a table entry — see
[`phishhawk/rules.py`](phishhawk/rules.py):

```python
def _check_my_heuristic(parsed, iocs):
    """Return evidence strings when the rule should fire, else []."""
    if "wire transfer" in parsed.subject.lower():
        return [f'subject mentions a wire transfer: "{parsed.subject}"']
    return []

Rule("CONT011", "Wire transfer in subject", 14, CATEGORY_CONTENT,
     "Payment redirection attempts often name the transfer up front.",
     _check_my_heuristic, mitre="T1657")
```

A rule that raises is caught and reported rather than aborting the scan, so a
bad heuristic can never cost you a whole triage run.

---

## Samples

Six synthetic messages in [`samples/`](samples/) exercise every rule category:
credential phishing, BEC wire fraud, malware delivery, a punycode homograph
attack, and two legitimate messages that must stay `BENIGN`.

All of them are fabricated. Domains are RFC 2606 reserved names or obvious
fakes, the "payload" is inert text, and nothing resolves. Regenerate them with
`python3 samples/make_samples.py`.

The test suite pins the expected verdict for each sample, so any scoring change
that would reclassify a message fails CI immediately.

---

## Tests

```bash
python3 -m unittest discover -s tests -v
```

146 tests covering MIME parsing, IOC extraction, every detection rule, the
scoring engine, all five output formats and the full CLI surface. Runs in well
under a second, on CPython 3.10 through 3.13.

Two properties are worth calling out, because they are what keep the tool
honest:

- **No rule may error on any input.** Empty files, binary garbage and malformed
  MIME are all asserted to parse without raising.
- **The legitimate samples must produce zero hard signals.** False positives on
  real mail are the fastest way to make a tool like this get ignored.

---

## Limitations

Worth knowing before you rely on it:

- **Heuristics, not verdicts.** The score reflects how a message *looks*, not
  ground truth. A targeted, well-written spear-phish with a clean domain and no
  attachment can score low. Corroborate before acting.
- **No live lookups.** Offline is a deliberate design choice, so there is no
  DNS, no WHOIS age check, no URL detonation, no reputation feed. PhishHawk
  tells you what to check; it does not check it for you.
- **Authentication results are taken on trust.** They are read from the headers
  your MTA wrote. If the message never passed through a trusted MTA, they can be
  forged — which is exactly why `AUTH004` fires when they are missing entirely.
- **Brand coverage is a fixed list.** Look-alike detection covers the ~40 most
  impersonated brands. Add your own employer to `WATCHED_BRANDS` and your real
  domains to `BRAND_DOMAINS` in [`phishhawk/iocs.py`](phishhawk/iocs.py) — that
  single change is the highest-value local customization you can make.
- **English-language content rules.** The content heuristics are English
  patterns; headers, URLs and attachment rules are language-independent.

---

## Handling live phishing safely

If you point this at real malicious mail:

- Extracted URLs are **defanged by default** in every human-facing output.
  `--fanged` exists for machine ingestion — do not paste its output into chat.
- PhishHawk **never opens attachments or fetches URLs.** It hashes attachment
  bytes and reports the digest; detonation is your sandbox's job.
- Work on copies in a directory you control, not in a live mailbox.

---

## License

MIT — see [LICENSE](LICENSE).

Built for defensive security work: triaging reported phishing, extracting
indicators, and explaining to a colleague *why* the email in their inbox is not
what it claims to be.
