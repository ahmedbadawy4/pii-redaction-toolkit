"""Command line: redact text from a file or standard input.

python -m piikit notes.txt
cat notes.txt | python -m piikit --style mask
python -m piikit --findings notes.txt   # JSON list of labels and spans
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from .detectors import default_detector_specs
from .redact import DetectorFailure, Style, redact, scan


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="piikit",
        description="Redact personal data and secrets from text.",
    )
    parser.add_argument("file", nargs="?", help="input file (default: standard input)")
    parser.add_argument(
        "--style",
        choices=[s.value for s in Style if s is not Style.TOKEN],
        default=Style.LABEL.value,
        help="how to replace a finding (default: label)",
    )
    parser.add_argument(
        "--findings",
        action="store_true",
        help="print findings as JSON (label and span only, never the value)",
    )
    parser.add_argument(
        "--phone-region",
        action="append",
        default=[],
        metavar="CC",
        help="also find local phone numbers for this country code (repeatable)",
    )
    args = parser.parse_args(argv)

    if args.file:
        with open(args.file, encoding="utf-8") as handle:
            text = handle.read()
    else:
        text = sys.stdin.read()

    specs = default_detector_specs(phone_regions=args.phone_region)
    if args.findings:
        findings = scan(text, specs)
        json.dump(
            [
                {
                    "type": f.type,
                    "label": f.label,
                    "start": f.span_start,
                    "end": f.span_end,
                    "confidence": f.confidence,
                }
                for f in findings
            ],
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
        return 0

    try:
        result = redact(text, specs, style=args.style)
    except DetectorFailure as exc:
        print(f"piikit: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(result.text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
