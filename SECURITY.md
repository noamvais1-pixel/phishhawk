# Security Policy

## Scope

PhishHawk parses **hostile input by design** — the whole point is to point it at
mail an attacker wrote. The security-relevant question is therefore not "can it
be tricked into a wrong verdict" (heuristics can always be evaded) but "can a
crafted message make PhishHawk do something it should not".

### In scope

- A crafted `.eml` that causes code execution, file writes outside the chosen
  output path, or a hang / unbounded memory growth (denial of service).
- Any path where PhishHawk **makes a network request**, opens an attachment, or
  renders remote content. It must never do any of these.
- Indicator leakage: a live, clickable URL appearing in output that is supposed
  to be defanged.
- HTML report injection: message content escaping into executable markup in a
  generated report.

### Out of scope

- A phishing message that scores lower than you think it should, or a
  legitimate message that scores higher. These are tuning issues — please open a
  normal issue with the message (redacted) and the rules that did or did not
  fire.
- Evasion of a specific heuristic. Detection rules are best-effort by nature.

## Reporting

Report suspected vulnerabilities through
[GitHub Security Advisories](https://github.com/noamvais1-pixel/phishhawk/security/advisories/new)
rather than a public issue.

Please include the message that triggers it. **Redact real recipient addresses
and any live indicators**, or describe the structure instead of attaching the
original.

## Design guarantees

These are enforced by the test suite and CI, not just intended:

| Guarantee | How it is enforced |
| --- | --- |
| No network access | No socket-capable import exists; `tools/check_stdlib_only.py` blocks new dependencies |
| No third-party code | Same check, run on every push |
| Attachments are never opened | Only hashed and measured; no extraction, no execution |
| Malformed input never crashes | Tests feed empty files, binary garbage and broken MIME |
| A failing rule cannot abort a scan | Rule exceptions are caught and reported as findings |
| Human-facing output is defanged | CI greps generated output for live URLs |
| HTML reports are self-contained | CI asserts no `<script>` and no external asset host |

## Handling real phishing safely

- Work on **copies** in a directory you control, never a live mailbox.
- `--fanged` output is for machine ingestion into a blocklist. Do not paste it
  into chat, tickets, or anywhere a client will linkify it.
- PhishHawk reports attachment hashes so you can look them up. Detonate in a
  sandbox — never open one on your analysis host.
