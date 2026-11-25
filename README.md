# pii-redaction-toolkit

[![CI](https://github.com/ahmedbadawy4/pii-redaction-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmedbadawy4/pii-redaction-toolkit/actions/workflows/ci.yml)

Find personal data and secrets in text and replace them. The import name is `piikit`.

This is a prototype. It is a set of patterns, checksums and small heuristics with a tested interface, not a privacy or compliance tool. Read [Limitations](#limitations) before you rely on it.

- Python 3.12 or newer.
- No runtime dependencies. Phone numbers and person names use optional packages.
- Three ways to replace a finding: a label, a mask or a reversible token.
- It folds common evasions (zero-width characters, look-alike letters, full-width digits) before it matches, and reports spans on your original text.

## Install

The package is not on PyPI yet. Install it from a clone:

```bash
pip install .
```

Optional extras:

```bash
pip install ".[phone]"   # phone numbers, uses phonenumbers
pip install ".[names]"   # person names from the US Census name lists
pip install ".[ner]"     # person names from spaCy (you also need a model such as en_core_web_sm)
```

## Quick start

```python
from piikit import redact, scan

text = "Mail jane.doe@example.com, card 4111 1111 1111 1111, IBAN GB29 NWBK 6016 1331 9268 19."

print(redact(text).text)
# Mail [EMAIL], card [CREDIT_CARD], IBAN [IBAN].

for finding in scan(text):
    print(finding.label, text[finding.span_start : finding.span_end])
# email jane.doe@example.com
# credit_card 4111 1111 1111 1111
# iban GB29 NWBK 6016 1331 9268 19
```

`scan` returns `Finding(type, label, span_start, span_end, confidence)` objects sorted by position. Where two findings overlap, the one with the higher confidence wins, then the longer span, then the earlier start.

## Styles

```python
from piikit import Style, redact, restore

redact(text, style=Style.LABEL).text
# Mail [EMAIL], card [CREDIT_CARD], IBAN [IBAN].

redact(text, style=Style.MASK).text
# Mail ********************, card *******************, IBAN ***************************.

result = redact(text, style=Style.TOKEN)
result.text
# Mail <EMAIL_1>, card <CREDIT_CARD_1>, IBAN <IBAN_1>.
result.mapping
# {'<EMAIL_1>': 'jane.doe@example.com', '<CREDIT_CARD_1>': '4111 1111 1111 1111', ...}
restore(result.text, result.mapping) == text
# True
```

The same value always gets the same token, so a reader can still tell that two mentions are the same one. Keep the mapping out of the text you share.

## What it finds

| Label | How it is found |
| --- | --- |
| `email` | Pattern. |
| `address` | Street addresses with a US-style street type, such as `221 Baker Street`. |
| `credit_card` | 13 to 19 digits with optional spaces or dashes, kept only if the Luhn check passes. |
| `iban` | Grouped or ungrouped, kept only if the mod-97 check passes. |
| `us_ssn` | Pattern with the invalid prefixes 000, 666 and 900-999 excluded. |
| `estonian_personal_code` | Eleven digits starting with 1 to 6, kept only if the check digit is right. |
| `phone` | The `phonenumbers` package. Numbers with a `+` are always checked; local numbers need `phone_regions`. Does nothing without the `phone` extra. |
| `person_name` | spaCy if it and a model are installed, otherwise the `names` package, otherwise nothing. |
| `github_pat` | Classic personal access tokens that start with `ghp_`. |
| `openai_api_key` | `sk-` followed by 20 or more letters or digits. |
| `aws_access_key_id` | `AKIA` followed by 16 capital letters or digits. |
| `aws_secret_access_key` | A 40-character value near the words "access key". Only the value is replaced. |
| `jwt` | Three dot-separated base64url parts, the first starting with `eyJ`. |
| `private_key` | A PEM private key block. |

For local phone numbers, or to turn names off:

```python
from piikit import default_detector_specs, redact

specs = default_detector_specs(phone_regions=["EE", "GB"], detect_names=False)
redact("call 5340 7772", specs).text
```

## Evasion folding

Before matching, the text is folded one character at a time: format characters such as zero-width spaces are dropped, a curated set of Cyrillic and Greek look-alike letters become Latin, full-width forms become ASCII, and combining marks are dropped. An index map keeps every character tied to its position in the original text, so a finding always points at the original characters and `redact` removes them exactly.

```python
token = "sk-" + "\u200b".join("a" * 30)  # zero-width spaces inside a key
redact(f"key: {token} end").text
# key: [OPENAI_API_KEY] end
```

## When a detector crashes

Every detector is declared `FAIL_CLOSED` or `FAIL_OPEN`. The built-in pattern detectors are fail-closed. The phone and name detectors are fail-open because they depend on optional packages.

- `scan` reports a fail-closed crash as a finding with type `detector_error`.
- `redact` raises `DetectorFailure` instead of returning text that may still hold personal data. The exception names the detectors in `exc.detectors`.
- A fail-open crash is ignored and the other detectors still run.

## Your own detectors

Anything with a `name` and a `detect(text) -> list[Finding]` method is a detector. `RegexDetector` covers the common case, and if a pattern has a group named `value`, only that group is reported.

```python
import re

from piikit import DetectorSpec, RegexDetector, default_detector_specs, redact

employee = RegexDetector("pii", [("employee_id", re.compile(r"\bEMP-\d{6}\b"))])
specs = (*default_detector_specs(), DetectorSpec(employee))

redact("Ticket for EMP-004217 from jane.doe@example.com", specs).text
# Ticket for [EMPLOYEE_ID] from [EMAIL]
```

`RegexDetector` also takes a `validators` mapping from label to a function that returns `False` to drop a match, and a `confidence` value for the findings it makes.

## Command line

```bash
printf 'Mail jane.doe@example.com or call +372 5340 7772\n' | python -m piikit
# Mail [EMAIL] or call [PHONE]       (the phone part needs the phone extra)

python -m piikit --style mask notes.txt
python -m piikit --phone-region EE notes.txt
python -m piikit --findings notes.txt    # JSON with label and span, never the value
```

The command is also installed as `piikit`. It exits with code 2 if a fail-closed detector crashed. It does not offer the token style, because the mapping would have nowhere to go.

## Limitations

- **Patterns and heuristics.** There is no machine-learning model in the core. A value that does not match a pattern is not found, and a value that looks like one can be a false match.
- **Nine-digit numbers.** A bare run of nine digits that passes the SSN rules is reported as an SSN, with or without dashes.
- **Names.** Name detection is optional and built for English. With neither spaCy nor the `names` package installed, no names are found. The `names` package is a word list, so it can flag two capitalised words that are not a person.
- **Addresses.** Only US-style street types are recognised.
- **Look-alike letters.** The map is a curated list of Cyrillic and Greek letters, not the full Unicode confusables data. Other scripts are not folded.
- **Mask style** keeps the length of each value, so the length leaks.
- **Restore** cannot tell a token that was already in your input from one that `redact` made.
- **The test corpus** in `tests/test_quality.py` is a regression guard, not a benchmark. It does not give you a recall or precision figure for your data.
- **Not a compliance tool.** Using it does not make a system meet GDPR, HIPAA, PCI DSS or any other rule.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[phone,names,dev]"

ruff check .
ruff format --check .
pytest
python -m build
```

Without the extras, the tests for phone numbers and names are skipped and the rest pass.

## Security

See [SECURITY.md](SECURITY.md).

## License

Copyright 2026 MASHREQ OÜ. All rights reserved. This is source-available software, not open source. You may read the code and run it locally to evaluate it. Any other use, including copying, changing, sharing or using it in a product or service, needs written permission from MASHREQ OÜ. See [LICENSE](LICENSE).
