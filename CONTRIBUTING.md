# Contributing to PhishHawk

Contributions are welcome. The most valuable ones are usually **new detection
rules** and **tuning fixes for false positives**.

## Ground rules

**No dependencies.** PhishHawk must run on an air-gapped analysis host with no
package index reachable. `tools/check_stdlib_only.py` enforces this in CI.

**No network calls.** Not for DNS, not for reputation, not for telemetry. If a
feature needs a lookup, it belongs in a separate tool that consumes PhishHawk's
JSON output.

**Every finding must carry evidence.** A rule that says "this looks suspicious"
without quoting what it saw is not useful to an analyst who has to make a
decision. Return the matched substring, the offending header, the actual URL.

## Getting set up

```bash
git clone https://github.com/noamvais1-pixel/phishhawk.git
cd phishhawk
python3 -m unittest discover -s tests -v
```

No virtualenv, no install step. Python 3.10+ is the only requirement.

## Adding a detection rule

Rules live in [`phishhawk/rules.py`](phishhawk/rules.py). A rule is a function
plus one table entry.

```python
def _check_wire_transfer_subject(parsed: ParsedEmail, iocs: IOCSet) -> Evidence:
    """Return evidence strings when the rule fires, or [] when it does not."""
    if "wire transfer" in parsed.subject.lower():
        return [f'subject mentions a wire transfer: "{parsed.subject}"']
    return []
```

Then register it in `ALL_RULES`:

```python
Rule("CONT011", "Wire transfer in subject", 14, CATEGORY_CONTENT,
     "Payment redirection attempts often name the transfer up front.",
     _check_wire_transfer_subject, mitre="T1657"),
```

### Choosing a weight

Weights are calibrated so a verdict always needs corroboration. Use the existing
rules as the reference scale:

| Weight | Meaning | Example |
| ---: | --- | --- |
| 24–30 | Strong on its own; rarely appears in legitimate mail | executable attachment, credential form in body |
| 16–22 | Substantial, but legitimate mail occasionally trips it | DMARC failure, display-name spoofing |
| 10–14 | Meaningful only alongside other signals | urgency language, URL shortener |
| 6–8 | Weak context | generic greeting, low-reputation TLD |

**No rule may score above 79.** Reaching `CRITICAL` from a single rule is a
design violation, and `TestRuleIntegrity` fails the build if you try.

If your rule is severe enough that it must always warrant a human look, add its
ID to `HARD_SIGNALS` in [`phishhawk/analyzer.py`](phishhawk/analyzer.py) instead
of inflating its weight. That prevents a `BENIGN` verdict without distorting
the arithmetic.

## Tests are required

Every rule needs both directions:

```python
def test_wire_transfer_subject_fires(self) -> None:
    raw = b"From: a@example.com\nSubject: Wire transfer request\n\nbody\n"
    self.assertIn("CONT011", _fired(analyze_bytes(raw)))

def test_ordinary_subject_does_not_fire(self) -> None:
    raw = b"From: a@example.com\nSubject: Lunch tomorrow?\n\nbody\n"
    self.assertNotIn("CONT011", _fired(analyze_bytes(raw)))
```

The negative test matters more than the positive one. **False positives are the
fastest way to make a tool like this get ignored**, so the suite also asserts
that the two legitimate samples produce zero hard signals and stay `BENIGN`.

If your change moves any sample's verdict, `TestSampleCorpusRegression` fails.
That is the check doing its job — update the pinned expectation only when the
new verdict is genuinely more correct, and say why in the pull request.

## Adding a sample

Samples must be **synthetic**. Never commit real mail: it contains real people's
addresses and live indicators.

Add it to [`samples/make_samples.py`](samples/make_samples.py), use RFC 2606
reserved domains (`example.com`, `example.org`) or obviously fake ones, keep any
"payload" inert, then regenerate:

```bash
python3 samples/make_samples.py
```

Pin its expected verdict in `TestSampleCorpusRegression.EXPECTED`.

## Reducing false positives

This is the highest-value contribution. If a legitimate message scores too high:

1. Run `python3 -m phishhawk scan message.eml -v` and read the `SCORING` block.
2. Decide whether the fix is a narrower rule, a lower weight, an entry in
   `BRAND_DOMAINS`, or a new mitigation.
3. Add the (synthetic, redacted) message as a sample so it stays fixed.

## Before opening a pull request

```bash
python3 -m unittest discover -s tests -v
python3 tools/check_stdlib_only.py
python3 samples/make_samples.py && git diff --exit-code -- samples/
```

Match the surrounding style: type hints, a docstring explaining *why* rather
than *what*, and no comments that narrate the next line.
