"""PhishHawk - offline phishing email triage and forensics toolkit."""

__version__ = "1.0.0"

from phishhawk.parser import ParsedEmail, parse_bytes, parse_file
from phishhawk.analyzer import Analysis, analyze
from phishhawk.iocs import IOCSet, extract_iocs

__all__ = [
    "__version__",
    "ParsedEmail",
    "parse_bytes",
    "parse_file",
    "Analysis",
    "analyze",
    "IOCSet",
    "extract_iocs",
]
