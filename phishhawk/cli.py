"""Command-line interface for PhishHawk.

Sub-commands
------------
``scan``     deep report on one or more messages
``triage``   batch-score a folder or mailbox, worst first
``iocs``     emit a flat, paste-ready indicator list
``headers``  render the delivery chain and authentication results
``rules``    list the detection rules and their weights
"""

from __future__ import annotations

import argparse
import mailbox
import os
import sys
from typing import Iterator, Sequence

from phishhawk import __version__
from phishhawk.analyzer import Analysis, analyze
from phishhawk.parser import parse_bytes
from phishhawk.report import (
    BANNER,
    format_csv,
    format_html,
    format_ioc_list,
    format_json,
    format_markdown,
    format_terminal,
    format_triage_table,
    use_color,
)
from phishhawk.rules import ALL_RULES, CONTEXT_RULES

EMAIL_SUFFIXES = (".eml", ".msg.eml", ".email", ".mail", ".txt")

EXIT_OK = 0
EXIT_FLAGGED = 1
EXIT_ERROR = 2
EXIT_NO_INPUT = 3

VERDICT_EXIT_ORDER = ["BENIGN", "LOW", "SUSPICIOUS", "HIGH", "CRITICAL"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishhawk",
        description="Offline phishing email triage and forensics. No network calls, no dependencies.",
        epilog="Everything runs locally: no message content ever leaves this machine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"phishhawk {__version__}")

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    def add_common(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("paths", nargs="*", metavar="PATH",
                         help="'.eml' files, directories, or mbox files. '-' reads stdin.")
        sub.add_argument("-r", "--recursive", action="store_true",
                         help="Recurse into subdirectories.")
        sub.add_argument("--disable", metavar="IDS", default="",
                         help="Comma-separated rule IDs to switch off (e.g. CONT001,URL009).")
        sub.add_argument("--no-color", action="store_true", help="Disable ANSI colour.")

    scan = subparsers.add_parser("scan", help="Deep-analyze one or more messages.")
    add_common(scan)
    scan.add_argument("-f", "--format", default="text",
                      choices=["text", "json", "markdown", "html", "csv"],
                      help="Output format (default: text).")
    scan.add_argument("-o", "--output", metavar="FILE", help="Write the report to FILE.")
    scan.add_argument("-v", "--verbose", action="store_true",
                      help="Show rule descriptions, all IOCs and parse notes.")

    triage = subparsers.add_parser("triage", help="Batch-score a folder, worst first.")
    add_common(triage)
    triage.add_argument("-f", "--format", default="table",
                        choices=["table", "json", "csv", "html", "markdown"],
                        help="Output format (default: table).")
    triage.add_argument("-o", "--output", metavar="FILE", help="Write the report to FILE.")
    triage.add_argument("--min-score", type=int, default=0, metavar="N",
                        help="Only report messages scoring at least N.")
    triage.add_argument("--verdict", metavar="LEVEL", default="BENIGN",
                        choices=VERDICT_EXIT_ORDER,
                        help="Only report messages at or above this verdict.")
    triage.add_argument("--fail-on", metavar="LEVEL", default="SUSPICIOUS",
                        choices=VERDICT_EXIT_ORDER,
                        help="Exit 1 when any message reaches this verdict (default: SUSPICIOUS).")

    iocs = subparsers.add_parser("iocs", help="Emit a flat indicator list.")
    add_common(iocs)
    iocs.add_argument("-o", "--output", metavar="FILE", help="Write the list to FILE.")
    iocs.add_argument("--fanged", action="store_true",
                      help="Emit live indicators instead of defanged ones. Handle with care.")

    headers = subparsers.add_parser("headers", help="Show the delivery chain and auth results.")
    add_common(headers)
    headers.add_argument("--all", action="store_true", help="Print every header, not just key ones.")

    rules_cmd = subparsers.add_parser("rules", help="List the detection rules.")
    rules_cmd.add_argument("--category", metavar="NAME", help="Filter by category.")
    rules_cmd.add_argument("-f", "--format", default="text", choices=["text", "json", "markdown"])
    rules_cmd.add_argument("--no-color", action="store_true")

    return parser


# --------------------------------------------------------------------------- #
# Input discovery
# --------------------------------------------------------------------------- #


def iter_messages(paths: Sequence[str], recursive: bool) -> Iterator[tuple[str, bytes]]:
    """Yield ``(label, raw_bytes)`` for every message reachable from ``paths``."""
    for path in paths:
        if path == "-":
            yield "<stdin>", sys.stdin.buffer.read()
        elif os.path.isdir(path):
            yield from _iter_directory(path, recursive)
        elif os.path.isfile(path):
            yield from _iter_file(path)
        else:
            print(f"phishhawk: no such file or directory: {path}", file=sys.stderr)


def _iter_directory(directory: str, recursive: bool) -> Iterator[tuple[str, bytes]]:
    if recursive:
        for root, _, files in os.walk(directory):
            for name in sorted(files):
                if name.lower().endswith(EMAIL_SUFFIXES):
                    yield from _iter_file(os.path.join(root, name))
    else:
        for name in sorted(os.listdir(directory)):
            full = os.path.join(directory, name)
            if os.path.isfile(full) and name.lower().endswith(EMAIL_SUFFIXES):
                yield from _iter_file(full)


def _iter_file(path: str) -> Iterator[tuple[str, bytes]]:
    try:
        with open(path, "rb") as handle:
            head = handle.read(5)
            handle.seek(0)
            raw = handle.read()
    except OSError as exc:
        print(f"phishhawk: cannot read {path}: {exc}", file=sys.stderr)
        return

    # An mbox always starts with "From " — unpack it into individual messages.
    if head == b"From ":
        try:
            box = mailbox.mbox(path)
            for index, message in enumerate(box):
                yield f"{path}[{index}]", message.as_bytes()
            return
        except Exception as exc:
            print(f"phishhawk: mbox read failed for {path} ({exc}); treating as one message",
                  file=sys.stderr)
    yield path, raw


def collect(args: argparse.Namespace) -> list[Analysis]:
    disabled = {r.strip().upper() for r in (args.disable or "").split(",") if r.strip()}
    results: list[Analysis] = []
    for label, raw in iter_messages(args.paths, getattr(args, "recursive", False)):
        if not raw.strip():
            print(f"phishhawk: skipping empty message: {label}", file=sys.stderr)
            continue
        results.append(analyze(parse_bytes(raw), source=label, disabled=disabled))
    return results


def _write(text: str, destination: str | None) -> None:
    if destination:
        with open(destination, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"phishhawk: wrote {destination}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def _exit_code(results: Sequence[Analysis], threshold: str) -> int:
    limit = VERDICT_EXIT_ORDER.index(threshold)
    worst = max((VERDICT_EXIT_ORDER.index(a.verdict) for a in results), default=0)
    return EXIT_FLAGGED if worst >= limit else EXIT_OK


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


def cmd_scan(args: argparse.Namespace) -> int:
    results = collect(args)
    if not results:
        print("phishhawk: no messages to analyze.", file=sys.stderr)
        return EXIT_NO_INPUT

    color = use_color(force=False if args.no_color else None)
    if args.format == "json":
        _write(format_json(results), args.output)
    elif args.format == "csv":
        _write(format_csv(results), args.output)
    elif args.format == "html":
        _write(format_html(results), args.output)
    elif args.format == "markdown":
        _write("\n\n---\n\n".join(format_markdown(r) for r in results), args.output)
    else:
        body = "".join(
            format_terminal(r, color=color and not args.output, verbose=args.verbose)
            for r in results
        )
        _write(body, args.output)

    return _exit_code(results, "SUSPICIOUS")


def cmd_triage(args: argparse.Namespace) -> int:
    results = collect(args)
    if not results:
        print("phishhawk: no messages to analyze.", file=sys.stderr)
        return EXIT_NO_INPUT

    floor = VERDICT_EXIT_ORDER.index(args.verdict)
    shown = [
        r for r in results
        if r.score >= args.min_score and VERDICT_EXIT_ORDER.index(r.verdict) >= floor
    ]

    color = use_color(force=False if args.no_color else None)
    if args.format == "json":
        _write(format_json(shown), args.output)
    elif args.format == "csv":
        _write(format_csv(shown), args.output)
    elif args.format == "html":
        _write(format_html(shown, title="PhishHawk triage report"), args.output)
    elif args.format == "markdown":
        _write("\n\n---\n\n".join(format_markdown(r) for r in shown), args.output)
    else:
        if not shown:
            print(f"phishhawk: {len(results)} message(s) analyzed, none met the filter.",
                  file=sys.stderr)
            return _exit_code(results, args.fail_on)
        _write(format_triage_table(shown, color=color and not args.output), args.output)
        if len(shown) != len(results):
            print(f"phishhawk: {len(results) - len(shown)} message(s) hidden by filters.",
                  file=sys.stderr)

    return _exit_code(results, args.fail_on)


def cmd_iocs(args: argparse.Namespace) -> int:
    results = collect(args)
    if not results:
        print("phishhawk: no messages to analyze.", file=sys.stderr)
        return EXIT_NO_INPUT
    _write(format_ioc_list(results, defanged=not args.fanged), args.output)
    return _exit_code(results, "SUSPICIOUS")


def cmd_headers(args: argparse.Namespace) -> int:
    results = collect(args)
    if not results:
        print("phishhawk: no messages to analyze.", file=sys.stderr)
        return EXIT_NO_INPUT

    color = use_color(force=False if args.no_color else None)
    from phishhawk.report import BOLD, DIM, RESET, VERDICT_PLAIN, _c

    for analysis in results:
        parsed = analysis.parsed
        assert parsed is not None
        print(f"\n{_c('══ ' + analysis.source, BOLD, color)}")
        print(f"{_c('subject', DIM, color)}  {parsed.subject}")
        print(f"{_c('from', DIM, color)}     {parsed.from_address}")

        print(f"\n{_c('authentication', BOLD, color)}")
        if parsed.auth_results:
            for mechanism, verdict in sorted(parsed.auth_results.items()):
                tint = VERDICT_PLAIN["BENIGN"] if verdict == "pass" else VERDICT_PLAIN["HIGH"]
                print(f"  {mechanism.upper():<8} {_c(verdict, tint, color)}")
        else:
            print(f"  {_c('no results recorded by any relay', DIM, color)}")

        print(f"\n{_c('delivery chain (origin first)', BOLD, color)}")
        if not parsed.received_chain:
            print(f"  {_c('no Received headers', DIM, color)}")
        for hop in parsed.received_chain:
            stamp = hop.timestamp.strftime("%Y-%m-%d %H:%M:%S %z") if hop.timestamp else "?"
            print(f"  {_c(f'[{hop.index}]', BOLD, color)} {hop.from_host or '?'} "
                  f"{_c('→', DIM, color)} {hop.by_host or '?'}")
            print(f"      ip={hop.ip or '-'}  proto={hop.protocol or '-'}  {_c(stamp, DIM, color)}")

        if args.all:
            print(f"\n{_c('all headers', BOLD, color)}")
            for key, value in parsed.headers:
                print(f"  {_c(key, DIM, color)}: {value[:400]}")
    print()
    return _exit_code(results, "SUSPICIOUS")


def cmd_rules(args: argparse.Namespace) -> int:
    from phishhawk.report import BOLD, DIM, _c

    color = use_color(force=False if args.no_color else None)
    rules = list(ALL_RULES) + list(CONTEXT_RULES)
    if args.category:
        wanted = args.category.lower()
        rules = [r for r in rules if r.category.lower() == wanted]
        if not rules:
            print(f"phishhawk: no rules in category {args.category!r}", file=sys.stderr)
            return EXIT_ERROR

    if args.format == "json":
        import json

        print(json.dumps([
            {"id": r.id, "name": r.name, "weight": r.weight, "category": r.category,
             "description": r.description, "mitre": r.mitre}
            for r in rules
        ], indent=2))
        return EXIT_OK

    if args.format == "markdown":
        print("| ID | Weight | Category | Rule | MITRE | Description |")
        print("| --- | ---: | --- | --- | --- | --- |")
        for rule in rules:
            print(f"| `{rule.id}` | {rule.weight} | {rule.category} | {rule.name} | "
                  f"{rule.mitre or '—'} | {rule.description} |")
        return EXIT_OK

    current = ""
    for rule in rules:
        if rule.category != current:
            current = rule.category
            print(f"\n{_c(current.upper(), BOLD, color)}")
        mitre = _c(f"  {rule.mitre}", DIM, color) if rule.mitre else ""
        print(f"  {_c(rule.id, BOLD, color)}  weight={rule.weight:<3} {rule.name}{mitre}")
        print(f"        {_c(rule.description, DIM, color)}")
    print(f"\n{len(rules)} rules")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        if use_color():
            sys.stdout.write(BANNER)
        parser.print_help()
        return EXIT_OK

    handlers = {
        "scan": cmd_scan,
        "triage": cmd_triage,
        "iocs": cmd_iocs,
        "headers": cmd_headers,
        "rules": cmd_rules,
    }
    try:
        return handlers[args.command](args)
    except BrokenPipeError:  # e.g. piping into `head`
        return EXIT_OK
    except KeyboardInterrupt:
        print("\nphishhawk: interrupted", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # pragma: no cover - top-level safety net
        print(f"phishhawk: unexpected error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
