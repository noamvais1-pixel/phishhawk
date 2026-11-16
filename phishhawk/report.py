"""Output formatters: terminal, JSON, CSV, Markdown and a standalone HTML report."""

from __future__ import annotations

import csv
import html
import io
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from phishhawk.analyzer import Analysis
from phishhawk.iocs import defang

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

VERDICT_COLORS = {
    "CRITICAL": "\033[97;41m",
    "HIGH": "\033[30;101m",
    "SUSPICIOUS": "\033[30;103m",
    "LOW": "\033[30;106m",
    "BENIGN": "\033[30;102m",
}

VERDICT_PLAIN = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[31m",
    "SUSPICIOUS": "\033[33m",
    "LOW": "\033[36m",
    "BENIGN": "\033[32m",
}

BANNER = r"""
  ___  _    _    _    _  _              _
 | _ \| |_ (_) __| |_ | || |__ _ __ __ | |__
 |  _/| ' \| |(_-<   \| __ / _` |\ V  V / / /
 |_|  |_||_|_|/__/_||_|_||_\__,_| \_/\_/|_\_\
   offline phishing triage  ·  no data leaves this machine
"""


def use_color(stream: Any = None, force: bool | None = None) -> bool:
    """Colour only when writing to a real terminal, unless overridden."""
    if force is not None:
        return force
    if os.environ.get("NO_COLOR"):
        return False
    stream = stream or sys.stdout
    return hasattr(stream, "isatty") and stream.isatty()


def _c(text: str, color: str, enabled: bool) -> str:
    return f"{color}{text}{RESET}" if enabled else text


def _bar(score: int, width: int = 30) -> str:
    filled = round(score / 100 * width)
    return "█" * filled + "░" * (width - filled)


def format_terminal(analysis: Analysis, color: bool = True, verbose: bool = False) -> str:
    """Full single-message report for a terminal."""
    out = io.StringIO()
    parsed = analysis.parsed
    verdict = analysis.verdict

    badge = _c(f" {verdict} ", VERDICT_COLORS.get(verdict, ""), color)
    out.write(f"\n{badge} {_c(f'score {analysis.score}/100', BOLD, color)}  "
              f"{_c(_bar(analysis.score), VERDICT_PLAIN.get(verdict, ''), color)}\n")
    if analysis.source:
        out.write(f"{_c('source', DIM, color)}      {analysis.source}\n")

    if parsed:
        out.write(f"{_c('subject', DIM, color)}     {parsed.subject or '(none)'}\n")
        sender = parsed.from_address or "(none)"
        display = f'"{parsed.from_display_name}" ' if parsed.from_display_name else ""
        out.write(f"{_c('from', DIM, color)}        {display}<{sender}>\n")
        if parsed.reply_to_addrs:
            replies = ", ".join(a for _, a in parsed.reply_to_addrs)
            out.write(f"{_c('reply-to', DIM, color)}    {replies}\n")
        if parsed.return_path:
            out.write(f"{_c('return-path', DIM, color)} {parsed.return_path}\n")
        recipients = ", ".join(a for _, a in parsed.to_addrs) or "(none)"
        out.write(f"{_c('to', DIM, color)}          {recipients}\n")
        out.write(f"{_c('date', DIM, color)}        {parsed.date_raw or '(none)'}\n")
        auth = parsed.auth_results
        auth_line = "  ".join(
            _c(f"{k.upper()}={v}", VERDICT_PLAIN["BENIGN"] if v == "pass" else VERDICT_PLAIN["HIGH"], color)
            for k, v in sorted(auth.items())
        ) or _c("none recorded", DIM, color)
        out.write(f"{_c('auth', DIM, color)}        {auth_line}\n")
        out.write(f"{_c('sha256', DIM, color)}      {parsed.sha256}\n")

    out.write(f"\n{_c('── FINDINGS ' + '─' * 58, BOLD, color)}\n")
    if not analysis.findings:
        out.write(f"  {_c('no detection rules fired', DIM, color)}\n")
    for finding in analysis.top_findings:
        marker = _c(f"[{finding.weight:>2}]", VERDICT_PLAIN["HIGH"] if finding.weight >= 20
                    else VERDICT_PLAIN["SUSPICIOUS"] if finding.weight >= 12
                    else VERDICT_PLAIN["LOW"], color)
        mitre = _c(f" ({finding.mitre})", DIM, color) if finding.mitre else ""
        out.write(f"  {marker} {_c(finding.rule_id, BOLD, color)} {finding.name}{mitre}\n")
        if verbose:
            out.write(f"       {_c(finding.description, DIM, color)}\n")
        for item in finding.evidence[:4]:
            out.write(f"       {_c('·', DIM, color)} {item}\n")

    for finding in analysis.context:
        out.write(f"  {_c('[ i]', DIM, color)} {_c(finding.rule_id, DIM, color)} {finding.name}\n")
        for item in finding.evidence[:2]:
            out.write(f"       {_c('·', DIM, color)} {item}\n")

    out.write(f"\n{_c('── SCORING ' + '─' * 59, BOLD, color)}\n")
    for line in analysis.score_breakdown:
        out.write(f"  +{line}\n")
    for line in analysis.mitigations:
        out.write(f"  {_c(line, VERDICT_PLAIN['BENIGN'], color)}\n")
    out.write(f"  {_c('=', BOLD, color)} {_c(str(analysis.score) + '/100', BOLD, color)} "
              f"→ {_c(verdict, VERDICT_PLAIN.get(verdict, ''), color)}\n")

    if analysis.mitre_techniques:
        out.write(f"\n{_c('── MITRE ATT&CK ' + '─' * 54, BOLD, color)}\n")
        out.write("  " + ", ".join(analysis.mitre_techniques) + "\n")

    out.write(f"\n{_c('── INDICATORS (defanged) ' + '─' * 45, BOLD, color)}\n")
    _write_iocs(out, analysis, color, verbose)

    out.write(f"\n{_c('── RECOMMENDED ACTIONS ' + '─' * 47, BOLD, color)}\n")
    for action in analysis.recommended_actions():
        out.write(f"  → {action}\n")

    if parsed and parsed.parse_errors and verbose:
        out.write(f"\n{_c('── PARSE NOTES ' + '─' * 55, BOLD, color)}\n")
        for note in parsed.parse_errors:
            out.write(f"  ! {note}\n")

    out.write("\n")
    return out.getvalue()


def _write_iocs(out: io.StringIO, analysis: Analysis, color: bool, verbose: bool) -> None:
    iocs = analysis.iocs
    limit = 100 if verbose else 12

    if iocs.urls:
        out.write(f"  {_c('urls', DIM, color)}\n")
        for url in iocs.urls[:limit]:
            flags = f"  {_c('[' + ', '.join(url.flags) + ']', VERDICT_PLAIN['SUSPICIOUS'], color)}" if url.flags else ""
            out.write(f"    {defang(url.url)[:150]}{flags}\n")
        if len(iocs.urls) > limit:
            out.write(f"    {_c(f'... {len(iocs.urls) - limit} more (use -v)', DIM, color)}\n")

    for label, values in (
        ("domains", sorted(iocs.domains)),
        ("ips", sorted(iocs.ips)),
        ("emails", sorted(iocs.emails)),
    ):
        if values:
            shown = [defang(v) for v in values[:limit]]
            suffix = f" ... +{len(values) - limit}" if len(values) > limit else ""
            out.write(f"  {_c(label, DIM, color)}\n    {', '.join(shown)}{suffix}\n")

    if analysis.parsed and analysis.parsed.attachments:
        out.write(f"  {_c('attachments', DIM, color)}\n")
        for attachment in analysis.parsed.attachments:
            out.write(f"    {attachment.filename} ({attachment.content_type}, "
                      f"{attachment.size} B)\n      sha256={attachment.sha256}\n")


def format_triage_table(analyses: Sequence[Analysis], color: bool = True) -> str:
    """One-line-per-message summary table, worst first."""
    out = io.StringIO()
    ordered = sorted(analyses, key=lambda a: a.score, reverse=True)

    name_width = min(38, max([len(_short(a.source)) for a in ordered] + [8]))
    header = f"{'VERDICT':<11} {'SCORE':>5}  {'FILE':<{name_width}}  {'FROM':<32}  SUBJECT"
    out.write(_c(header, BOLD, color) + "\n")
    out.write(_c("─" * min(160, len(header) + 40), DIM, color) + "\n")

    for analysis in ordered:
        verdict = _c(f"{analysis.verdict:<11}", VERDICT_PLAIN.get(analysis.verdict, ""), color)
        sender = (analysis.parsed.from_address if analysis.parsed else "")[:32]
        subject = (analysis.parsed.subject if analysis.parsed else "").replace("\n", " ")[:60]
        out.write(f"{verdict} {analysis.score:>5}  {_short(analysis.source):<{name_width}}  "
                  f"{sender:<32}  {subject}\n")

    out.write("\n" + _c("summary  ", BOLD, color))
    counts: dict[str, int] = {}
    for analysis in ordered:
        counts[analysis.verdict] = counts.get(analysis.verdict, 0) + 1
    parts = [
        _c(f"{verdict}={counts[verdict]}", VERDICT_PLAIN[verdict], color)
        for verdict in ("CRITICAL", "HIGH", "SUSPICIOUS", "LOW", "BENIGN")
        if verdict in counts
    ]
    out.write("  ".join(parts) + f"   total={len(ordered)}\n")
    return out.getvalue()


def _short(path: str, width: int = 38) -> str:
    name = os.path.basename(path) or path
    return name if len(name) <= width else "…" + name[-(width - 1):]


def format_json(analyses: Sequence[Analysis], indent: int = 2) -> str:
    payload = {
        "tool": "phishhawk",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(analyses),
        "results": [a.to_dict() for a in analyses],
    }
    return json.dumps(payload, indent=indent, ensure_ascii=False, default=str)


def format_csv(analyses: Sequence[Analysis]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow([
        "file", "verdict", "score", "from", "from_domain", "reply_to", "subject",
        "date", "spf", "dkim", "dmarc", "attachments", "urls",
        "rules_fired", "mitre", "sha256",
    ])
    for analysis in sorted(analyses, key=lambda a: a.score, reverse=True):
        parsed = analysis.parsed
        writer.writerow([
            analysis.source,
            analysis.verdict,
            analysis.score,
            parsed.from_address if parsed else "",
            parsed.from_domain if parsed else "",
            ";".join(a for _, a in parsed.reply_to_addrs) if parsed else "",
            (parsed.subject if parsed else "").replace("\n", " "),
            parsed.date_raw if parsed else "",
            parsed.auth_results.get("spf", "") if parsed else "",
            parsed.auth_results.get("dkim", "") if parsed else "",
            parsed.auth_results.get("dmarc", "") if parsed else "",
            len(parsed.attachments) if parsed else 0,
            len(analysis.iocs.urls),
            ";".join(f.rule_id for f in analysis.top_findings),
            ";".join(analysis.mitre_techniques),
            parsed.sha256 if parsed else "",
        ])
    return out.getvalue()


def format_ioc_list(analyses: Sequence[Analysis], defanged: bool = True) -> str:
    """Flat, paste-ready indicator list for blocklists and threat-intel platforms."""
    from phishhawk.iocs import merge_iocs

    merged = merge_iocs(a.iocs for a in analyses)
    transform = defang if defanged else (lambda v: v)
    out = io.StringIO()

    sections: list[tuple[str, Iterable[str]]] = [
        ("# urls", sorted({u.url for u in merged.urls})),
        ("# domains", sorted(merged.domains)),
        ("# ips", sorted(merged.ips)),
        ("# emails", sorted(merged.emails)),
        ("# sha256", sorted(merged.hashes["sha256"])),
    ]
    for header, values in sections:
        values = list(values)
        if not values:
            continue
        out.write(f"{header} ({len(values)})\n")
        for value in values:
            out.write(transform(value) + "\n" if header != "# sha256" else value + "\n")
        out.write("\n")
    return out.getvalue()


def format_markdown(analysis: Analysis) -> str:
    """A ticket-ready write-up for one message."""
    parsed = analysis.parsed
    lines = [
        f"# PhishHawk report — {analysis.verdict} ({analysis.score}/100)",
        "",
        f"- **Source:** `{analysis.source}`",
    ]
    if parsed:
        lines += [
            f"- **Subject:** {parsed.subject or '_(none)_'}",
            f"- **From:** `{parsed.from_address}`"
            + (f" (display name: {parsed.from_display_name})" if parsed.from_display_name else ""),
            f"- **Reply-To:** " + (", ".join(f"`{a}`" for _, a in parsed.reply_to_addrs) or "_(none)_"),
            f"- **Date:** {parsed.date_raw or '_(none)_'}",
            f"- **Auth:** " + (", ".join(f"{k.upper()}={v}" for k, v in sorted(parsed.auth_results.items())) or "_none recorded_"),
            f"- **Message SHA-256:** `{parsed.sha256}`",
        ]
    if analysis.mitre_techniques:
        lines.append(f"- **MITRE ATT&CK:** {', '.join(analysis.mitre_techniques)}")

    lines += ["", "## Findings", ""]
    if analysis.findings:
        lines += ["| Weight | Rule | Name | Evidence |", "| ---: | --- | --- | --- |"]
        for finding in analysis.top_findings:
            evidence = "<br>".join(e.replace("|", "\\|") for e in finding.evidence[:3])
            lines.append(f"| {finding.weight} | `{finding.rule_id}` | {finding.name} | {evidence} |")
    else:
        lines.append("_No detection rules fired._")

    lines += ["", "## Scoring", "", "```"]
    lines += [f"+{line}" for line in analysis.score_breakdown]
    lines += list(analysis.mitigations)
    lines += [f"= {analysis.score}/100 → {analysis.verdict}", "```", "", "## Indicators", ""]

    defanged = analysis.iocs.defanged()
    for label in ("urls", "domains", "ips", "emails"):
        values = defanged.get(label, [])
        if values:
            lines.append(f"**{label}**")
            lines.append("")
            lines += [f"- `{v}`" for v in values[:40]]
            lines.append("")

    if parsed and parsed.attachments:
        lines += ["**attachments**", ""]
        lines += [f"- `{a.filename}` — {a.content_type}, {a.size} B, sha256 `{a.sha256}`"
                  for a in parsed.attachments]
        lines.append("")

    lines += ["## Recommended actions", ""]
    lines += [f"{i}. {action}" for i, action in enumerate(analysis.recommended_actions(), 1)]
    lines += ["", "---", "",
              f"_Generated offline by PhishHawk at {datetime.now(timezone.utc).isoformat()}._"]
    return "\n".join(lines) + "\n"


_HTML_CSS = """
:root{color-scheme:dark;--bg:#0f1117;--card:#171a23;--line:#262b38;--fg:#e6e8ee;--dim:#8b93a7;
--crit:#ff4757;--high:#ff7f50;--susp:#ffc048;--low:#4bcffa;--benign:#32d296;--accent:#7d5fff}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1rem;background:var(--bg);color:var(--fg);
font:15px/1.6 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1080px;margin:0 auto}
h1{font-size:1.6rem;margin:0 0 .25rem}
h2{font-size:1.05rem;margin:2rem 0 .75rem;color:var(--dim);text-transform:uppercase;
letter-spacing:.08em;font-weight:600}
.sub{color:var(--dim);margin-bottom:2rem;font-size:.9rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:1.1rem 1.25rem;margin-bottom:1rem}
.badge{display:inline-block;padding:.3rem .85rem;border-radius:999px;font-weight:700;
font-size:.8rem;letter-spacing:.06em;color:#0f1117}
.CRITICAL{background:var(--crit)}.HIGH{background:var(--high)}.SUSPICIOUS{background:var(--susp)}
.LOW{background:var(--low)}.BENIGN{background:var(--benign)}
.meter{height:8px;background:#0b0d13;border-radius:999px;overflow:hidden;margin:.85rem 0}
.meter>div{height:100%;border-radius:999px}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th,td{text-align:left;padding:.55rem .6rem;border-bottom:1px solid var(--line);
vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.06em}
tr:last-child td{border-bottom:none}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.83rem}
code{background:#0b0d13;padding:.12rem .4rem;border-radius:4px;color:#b9c0d4;
overflow-wrap:anywhere}
td code{white-space:nowrap}
td:last-child code{white-space:normal}
pre{background:#0b0d13;padding:.9rem;border-radius:8px;overflow-x:auto;
border:1px solid var(--line);color:#b9c0d4}
.kv{display:grid;grid-template-columns:150px 1fr;gap:.4rem 1rem;font-size:.9rem}
.kv dt{color:var(--dim)}.kv dd{margin:0;word-break:break-word}
.w{display:inline-block;min-width:2.1rem;text-align:center;border-radius:5px;
padding:.05rem .35rem;font-weight:700;font-size:.78rem;color:#0f1117}
ul{margin:.4rem 0;padding-left:1.2rem}li{margin:.25rem 0}
.pass{color:var(--benign)}.faill{color:var(--crit)}
.tag{display:inline-block;background:#0b0d13;border:1px solid var(--line);color:var(--dim);
border-radius:5px;padding:.06rem .4rem;margin:.1rem .2rem .1rem 0;font-size:.76rem}
footer{color:var(--dim);font-size:.8rem;margin-top:2.5rem;border-top:1px solid var(--line);
padding-top:1rem}
"""


def _weight_color(weight: int) -> str:
    if weight >= 24:
        return "var(--crit)"
    if weight >= 16:
        return "var(--high)"
    if weight >= 10:
        return "var(--susp)"
    return "var(--low)"


def format_html(analyses: Sequence[Analysis], title: str = "PhishHawk report") -> str:
    """Self-contained HTML report — no external assets, safe to email or archive."""
    esc = html.escape
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='color-scheme' content='dark'>",
        f"<title>{esc(title)}</title><style>{_HTML_CSS}</style></head><body><div class='wrap'>",
        f"<h1>{esc(title)}</h1>",
        f"<p class='sub'>{len(analyses)} message(s) analyzed offline · "
        f"generated {esc(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))}</p>",
    ]

    if len(analyses) > 1:
        counts: dict[str, int] = {}
        for analysis in analyses:
            counts[analysis.verdict] = counts.get(analysis.verdict, 0) + 1
        parts.append("<div class='card'><h2 style='margin-top:0'>Triage summary</h2>")
        parts.append("<p>" + " ".join(
            f"<span class='badge {v}'>{v} {counts[v]}</span>"
            for v in ("CRITICAL", "HIGH", "SUSPICIOUS", "LOW", "BENIGN") if v in counts
        ) + "</p>")
        parts.append("<div class='scroll'><table><tr><th>Verdict</th><th>Score</th><th>File</th>"
                     "<th>From</th><th>Subject</th></tr>")
        for analysis in sorted(analyses, key=lambda a: a.score, reverse=True):
            parsed = analysis.parsed
            parts.append(
                f"<tr><td><span class='badge {analysis.verdict}'>{analysis.verdict}</span></td>"
                f"<td>{analysis.score}</td><td><code>{esc(_short(analysis.source, 44))}</code></td>"
                f"<td><code>{esc(parsed.from_address if parsed else '')}</code></td>"
                f"<td>{esc((parsed.subject if parsed else '')[:80])}</td></tr>"
            )
        parts.append("</table></div></div>")

    for analysis in sorted(analyses, key=lambda a: a.score, reverse=True):
        parts.append(_html_one(analysis, esc))

    parts.append("<footer>PhishHawk — offline phishing triage. "
                 "Scores are heuristic; always corroborate before acting.</footer>")
    parts.append("</div></body></html>")
    return "".join(parts)


def _html_one(analysis: Analysis, esc: Any) -> str:
    parsed = analysis.parsed
    color = {"CRITICAL": "var(--crit)", "HIGH": "var(--high)", "SUSPICIOUS": "var(--susp)",
             "LOW": "var(--low)", "BENIGN": "var(--benign)"}[analysis.verdict]
    out = ["<div class='card'>"]
    out.append(f"<span class='badge {analysis.verdict}'>{analysis.verdict}</span> "
               f"<strong style='margin-left:.5rem'>{analysis.score}/100</strong>")
    # the bar repeats the score printed just above it, so hide it from screen readers
    out.append(f"<div class='meter' aria-hidden='true'><div style='width:{analysis.score}%;background:{color}'></div></div>")

    out.append("<dl class='kv'>")
    out.append(f"<dt>Source</dt><dd><code>{esc(analysis.source)}</code></dd>")
    if parsed:
        auth = " ".join(
            f"<span class='{'pass' if v == 'pass' else 'faill'}'>{k.upper()}={v}</span>"
            for k, v in sorted(parsed.auth_results.items())
        ) or "<span class='tag'>none recorded</span>"
        out.append(f"<dt>Subject</dt><dd>{esc(parsed.subject) or '<em>none</em>'}</dd>")
        out.append(f"<dt>From</dt><dd>{esc(parsed.from_display_name)} "
                   f"<code>{esc(parsed.from_address)}</code></dd>")
        if parsed.reply_to_addrs:
            out.append("<dt>Reply-To</dt><dd>" + ", ".join(
                f"<code>{esc(a)}</code>" for _, a in parsed.reply_to_addrs) + "</dd>")
        if parsed.return_path:
            out.append(f"<dt>Return-Path</dt><dd><code>{esc(parsed.return_path)}</code></dd>")
        out.append(f"<dt>Date</dt><dd>{esc(parsed.date_raw)}</dd>")
        out.append(f"<dt>Authentication</dt><dd>{auth}</dd>")
        out.append(f"<dt>SHA-256</dt><dd><code>{esc(parsed.sha256)}</code></dd>")
    if analysis.mitre_techniques:
        out.append("<dt>MITRE ATT&amp;CK</dt><dd>" + " ".join(
            f"<span class='tag'>{esc(t)}</span>" for t in analysis.mitre_techniques) + "</dd>")
    out.append("</dl>")

    out.append("<h2>Findings</h2>")
    if analysis.findings:
        out.append("<div class='scroll'><table><tr><th>W</th><th>Rule</th><th>Evidence</th></tr>")
        for finding in analysis.top_findings:
            evidence = "<br>".join(f"<code>{esc(e[:220])}</code>" for e in finding.evidence[:4])
            out.append(
                f"<tr><td><span class='w' style='background:{_weight_color(finding.weight)}'>"
                f"{finding.weight}</span></td>"
                f"<td><strong>{esc(finding.rule_id)}</strong><br>{esc(finding.name)}"
                + (f"<br><span class='tag'>{esc(finding.mitre)}</span>" if finding.mitre else "")
                + f"</td><td>{evidence}</td></tr>"
            )
        out.append("</table></div>")
    else:
        out.append("<p>No detection rules fired.</p>")

    breakdown = "\n".join(f"+{line}" for line in analysis.score_breakdown)
    mitigations = "\n".join(analysis.mitigations)
    out.append("<h2>Scoring</h2><pre>" + esc(
        f"{breakdown}\n{mitigations}\n= {analysis.score}/100 → {analysis.verdict}".strip()
    ) + "</pre>")

    out.append("<h2>Indicators (defanged)</h2>")
    defanged = analysis.iocs.defanged()
    for label in ("urls", "domains", "ips", "emails"):
        values = defanged.get(label, [])
        if values:
            out.append(f"<p><strong>{label}</strong><br>" + "<br>".join(
                f"<code>{esc(v[:200])}</code>" for v in values[:50]) + "</p>")
    if parsed and parsed.attachments:
        out.append("<p><strong>attachments</strong></p><div class='scroll'><table>"
                   "<tr><th>Name</th><th>Type</th><th>Size</th><th>SHA-256</th></tr>")
        for attachment in parsed.attachments:
            out.append(f"<tr><td><code>{esc(attachment.filename)}</code></td>"
                       f"<td>{esc(attachment.content_type)}</td><td>{attachment.size}</td>"
                       f"<td><code>{esc(attachment.sha256)}</code></td></tr>")
        out.append("</table></div>")

    out.append("<h2>Recommended actions</h2><ul>" + "".join(
        f"<li>{esc(a)}</li>" for a in analysis.recommended_actions()) + "</ul>")
    out.append("</div>")
    return "".join(out)
