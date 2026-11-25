"""Detectors for personal data and secrets, and the pipeline that runs them.

A detector is any object with a ``name`` and a ``detect(text)`` method that
returns a list of :class:`~piikit.models.Finding`. ``run_detectors`` folds
common evasion tricks out of the text first, runs every enabled detector, and
maps each span back onto the original text.
"""

from __future__ import annotations

import functools
import importlib.util
import re
import unicodedata
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from .models import DETECTOR_ERROR, Finding

# ---------------------------------------------------------------------------
# Evasion folding
# ---------------------------------------------------------------------------

# Cyrillic and Greek letters that look like Latin ones. A curated list of the
# letters that show up in substitution tricks (for example a Cyrillic "а" inside
# an e-mail address), not the full Unicode confusables database. Extend it when
# a new evasion turns up.
_HOMOGLYPH_TO_LATIN = {
    # Cyrillic lowercase
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ѕ": "s",
    "ј": "j",
    "һ": "h",
    # Cyrillic uppercase
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",
    # Greek lowercase
    "α": "a",
    "ο": "o",
    "ρ": "p",
}


def _normalize_for_detection(text: str) -> tuple[str, list[int]]:
    """Fold common evasion tricks and keep a map back to the original text.

    One pass, per character:

    - homoglyphs (Cyrillic and Greek look-alikes) become their Latin letter
    - compatibility forms fold through NFKD, so fullwidth digits become ASCII
    - combining accents are dropped, so "e" plus an acute accent becomes "e"
    - invisible formatting characters (Unicode category Cf, such as zero-width
      spaces and the byte order mark) are dropped

    The returned list has one entry per character of the folded text: the index
    of the original character it came from. Redaction slices the original text,
    so spans must map back exactly, not approximately.
    """
    chars: list[str] = []
    index_map: list[int] = []
    for i, ch in enumerate(text):
        if unicodedata.category(ch) == "Cf":
            continue
        folded = _HOMOGLYPH_TO_LATIN.get(ch, ch)
        for part in unicodedata.normalize("NFKD", folded):
            if unicodedata.combining(part):
                continue
            chars.append(part)
            index_map.append(i)
    return "".join(chars), index_map


def _remap_span_to_original(
    span_start: int,
    span_end: int,
    index_map: list[int],
    original_len: int,
) -> tuple[int, int]:
    if span_end <= span_start:
        orig = index_map[span_start] if span_start < len(index_map) else original_len
        return orig, orig
    orig_start = index_map[span_start] if span_start < len(index_map) else original_len
    orig_end = (
        index_map[span_end - 1] + 1 if span_end - 1 < len(index_map) else original_len
    )
    return orig_start, orig_end


# ---------------------------------------------------------------------------
# Detector contract
# ---------------------------------------------------------------------------


class DetectorFailureMode(StrEnum):
    """What the pipeline does when a detector raises.

    ``FAIL_OPEN`` ignores the error and carries on. ``FAIL_CLOSED`` emits a
    ``detector_error`` finding so the caller knows the scan is incomplete.
    """

    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"


class Detector(Protocol):
    @property
    def name(self) -> str: ...

    def detect(self, text: str) -> list[Finding]: ...


@dataclass(frozen=True)
class DetectorSpec:
    detector: Detector
    failure_mode: DetectorFailureMode = DetectorFailureMode.FAIL_OPEN
    enabled: bool = True


def _error_finding(detector_name: str) -> Finding:
    return Finding(
        type=DETECTOR_ERROR,
        label=detector_name,
        span_start=0,
        span_end=0,
        confidence=1.0,
    )


# ---------------------------------------------------------------------------
# Checksum validators
# ---------------------------------------------------------------------------


def _luhn_valid(raw: str) -> bool:
    """True if the digits pass the Luhn check and number 13 to 19."""
    digits = [int(c) for c in raw if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _iban_valid(raw: str) -> bool:
    """True if the IBAN passes the ISO 13616 mod-97 check."""
    iban = re.sub(r"\s", "", raw).upper()
    if not 15 <= len(iban) <= 34:
        return False
    # Move the first four characters to the end, then turn letters into
    # numbers (A=10 ... Z=35).
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def _estonian_personal_code_valid(raw: str) -> bool:
    """True if an 11-digit Estonian personal code has a correct check digit."""
    code = re.sub(r"\D", "", raw)
    if len(code) != 11:
        return False
    weights_1 = (1, 2, 3, 4, 5, 6, 7, 8, 9, 1)
    weights_2 = (3, 4, 5, 6, 7, 8, 9, 1, 2, 3)
    digits = [int(ch) for ch in code]
    checksum = sum(d * w for d, w in zip(digits[:10], weights_1, strict=True)) % 11
    if checksum == 10:
        checksum = sum(d * w for d, w in zip(digits[:10], weights_2, strict=True)) % 11
        if checksum == 10:
            checksum = 0
    return checksum == digits[10]


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RegexDetector:
    """Runs labelled regular expressions over the text.

    If a pattern has a named group ``value``, only that group is reported, so a
    pattern can use surrounding context without redacting it. ``validators`` maps
    a label to a function that receives the matched value and returns False to
    discard the match (Luhn, IBAN mod-97 and similar checks).
    """

    name: str
    patterns: Sequence[tuple[str, re.Pattern[str]]]
    confidence: float = 1.0
    validators: dict[str, Callable[[str], bool]] | None = None

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for label, pattern in self.patterns:
            use_group = "value" in pattern.groupindex
            for match in pattern.finditer(text):
                start, end = match.span("value") if use_group else match.span()
                validate = (self.validators or {}).get(label)
                if validate is not None and not validate(text[start:end]):
                    continue
                findings.append(
                    Finding(
                        type=self.name,
                        label=label,
                        span_start=start,
                        span_end=end,
                        confidence=self.confidence,
                    )
                )
        return findings


class IbanDetector:
    """IBANs, compact (``GB29NWBK60161331926819``) or in groups of four
    (``GB29 NWBK 6016 1331 9268 19``), confirmed by the mod-97 checksum.

    When uppercase words follow the number the detector tries the shorter
    candidates too, so ``... 9268 19 FOR THE TRANSFER`` still matches.
    """

    name = "pii"

    _START = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]*")
    _NEXT = re.compile(r" [A-Z0-9]{1,4}(?!\w)")

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        resume_at = 0
        for start_match in self._START.finditer(text):
            start = start_match.start()
            if start < resume_at:
                continue
            ends = [start_match.end()]
            if start_match.end() - start <= 4:  # grouped form: "GB29 NWBK ..."
                while next_match := self._NEXT.match(text, ends[-1]):
                    ends.append(next_match.end())
            for end in reversed(ends):
                if end < len(text) and (text[end].isalnum() or text[end] == "_"):
                    continue
                if _iban_valid(text[start:end]):
                    findings.append(Finding("pii", "iban", start, end, 1.0))
                    resume_at = end
                    break
        return findings


class PhoneNumberDetector:
    """Phone numbers, using the ``phonenumbers`` package (libphonenumber).

    International numbers (``+372 5340 7772``) are found out of the box. Pass
    ``regions=("EE", "GB")`` to also find local numbers without a country prefix.
    Without the package installed, ``detect`` returns nothing; check
    ``available``.
    """

    name = "pii"

    def __init__(self, regions: Sequence[str] = ()) -> None:
        # None means: require an explicit +country prefix.
        self._regions: tuple[str | None, ...] = (
            None,
            *(r.strip().upper() for r in regions if r.strip()),
        )

    @property
    def available(self) -> bool:
        return importlib.util.find_spec("phonenumbers") is not None

    def detect(self, text: str) -> list[Finding]:
        if not self.available:
            return []
        import phonenumbers

        findings: list[Finding] = []
        seen: set[tuple[int, int]] = set()
        for region in self._regions:
            for match in phonenumbers.PhoneNumberMatcher(text, region):
                span = (match.start, match.end)
                if span in seen:
                    continue
                seen.add(span)
                findings.append(
                    Finding(
                        type="pii",
                        label="phone",
                        span_start=match.start,
                        span_end=match.end,
                        confidence=0.9,
                    )
                )
        return findings


@functools.lru_cache(maxsize=1)
def _load_spacy_model() -> Callable[[str], Any] | None:
    try:
        import spacy
    except Exception:  # not installed, or broken on this Python version
        return None
    for model in ("en_core_web_sm", "en_core_web_md", "en_core_web_lg"):
        try:
            return spacy.load(model)
        except OSError:
            continue
    return None


class SpacyNERDetector:
    """Person names from spaCy's named entity recognition.

    Needs ``pip install spacy`` and a model such as ``en_core_web_sm``. Without
    them ``detect`` returns nothing; check ``available``. Pass ``nlp`` to use a
    pipeline you loaded yourself.
    """

    name = "pii"

    def __init__(self, nlp: Callable[[str], Any] | None = None) -> None:
        self._nlp = nlp if nlp is not None else _load_spacy_model()

    @property
    def available(self) -> bool:
        return self._nlp is not None

    def detect(self, text: str) -> list[Finding]:
        if self._nlp is None:
            return []
        return [
            Finding(
                type="pii",
                label="person_name",
                span_start=ent.start_char,
                span_end=ent.end_char,
                confidence=0.85,
            )
            for ent in self._nlp(text).ents
            if ent.label_ == "PERSON"
        ]


class GazetteerNameDetector:
    """Person names found by lookup in the ``names`` package (US Census lists).

    Flags a run of two or more capitalised words that contains both a known
    first name and a known last name. It is a heuristic: it misses names that
    are not in the lists and can flag a product or place that looks like a name.
    Without the package installed ``detect`` returns nothing; check
    ``available``.
    """

    name = "pii"

    # Two or more consecutive TitleCase or UPPERCASE words.
    _CAP_SEQ = re.compile(
        r"\b(?:[A-Z][a-z]+|[A-Z]{2,})(?:\s+(?:[A-Z][a-z]+|[A-Z]{2,})){1,}\b"
    )

    def __init__(self) -> None:
        self._first_names, self._last_names = _load_name_lists()

    @property
    def available(self) -> bool:
        return bool(self._first_names)

    def detect(self, text: str) -> list[Finding]:
        if not self._first_names:
            return []
        findings: list[Finding] = []
        for match in self._CAP_SEQ.finditer(text):
            tokens = [t.upper() for t in match.group(0).split()]
            has_first = any(t in self._first_names for t in tokens)
            has_last = any(t in self._last_names for t in tokens)
            if has_first and has_last:
                findings.append(
                    Finding(
                        type="pii",
                        label="person_name",
                        span_start=match.start(),
                        span_end=match.end(),
                        confidence=0.75,
                    )
                )
        return findings


@functools.lru_cache(maxsize=1)
def _load_name_lists() -> tuple[frozenset[str], frozenset[str]]:
    spec = importlib.util.find_spec("names")
    if spec is None or spec.origin is None:
        return frozenset(), frozenset()
    data_dir = Path(spec.origin).parent

    def words(*filenames: str) -> frozenset[str]:
        found: set[str] = set()
        for filename in filenames:
            path = data_dir / filename
            if not path.exists():
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                parts = line.split()
                if parts and len(parts[0]) >= 2:
                    found.add(parts[0].upper())
        return frozenset(found)

    return words("dist.male.first", "dist.female.first"), words("dist.all.last")


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def run_detectors(text: str, detector_specs: Iterable[DetectorSpec]) -> list[Finding]:
    """Run every enabled detector over ``text`` and return all raw findings.

    Findings can overlap; use :func:`piikit.scan` to resolve overlaps. Spans
    always refer to the original ``text``.
    """
    folded, index_map = _normalize_for_detection(text)
    needs_remap = folded != text
    detect_text = folded if needs_remap else text

    findings: list[Finding] = []
    for spec in detector_specs:
        if not spec.enabled:
            continue
        try:
            detected = spec.detector.detect(detect_text)
        except Exception:
            if spec.failure_mode == DetectorFailureMode.FAIL_CLOSED:
                findings.append(_error_finding(spec.detector.name))
            continue
        if needs_remap:
            detected = [_to_original(f, index_map, len(text)) for f in detected]
        findings.extend(detected)
    return findings


def _to_original(finding: Finding, index_map: list[int], original_len: int) -> Finding:
    start, end = _remap_span_to_original(
        finding.span_start, finding.span_end, index_map, original_len
    )
    return replace(finding, span_start=start, span_end=end)


# Street address: a number, one to three words, and a known street-type word.
# The suffix list keeps "5 minutes later" style text from matching.
_STREET_TYPES = (
    r"(?:st(?:reet)?|ave(?:nue)?|rd|road|dr(?:ive)?|blvd|boulevard"
    r"|ln|lane|ct|court|cir(?:cle)?|pl(?:ace)?|way|hwy|highway"
    r"|pkwy|parkway|terr?(?:ace)?|trl|trail|sq(?:uare)?|loop)"
)

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_ADDRESS = re.compile(
    rf"\b\d{{1,6}}\s+(?:[A-Za-z]{{2,}}\s+){{1,3}}{_STREET_TYPES}\.?\b",
    re.IGNORECASE,
)
# Payment card: the regex finds 13 to 19 digits with optional spaces or dashes,
# _luhn_valid filters out the rest.
_CARD = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
# US SSN with or without separators. It rejects the invalid prefixes 000, 666
# and 900-999 and all-zero groups; the backreference keeps the separator the
# same in both places. A bare run of nine digits therefore also matches.
_SSN = re.compile(r"\b(?!000|666|9\d{2})\d{3}([-\s]?)(?!00)\d{2}\1(?!0000)\d{4}\b")
_ESTONIAN_CODE = re.compile(r"\b[1-6]\d{10}\b")

_GITHUB_PAT = re.compile(r"\bghp_[A-Za-z0-9]{36}\b")
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
_AWS_ACCESS_KEY_ID = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
# Only the 40-character value is reported, not the words before it.
_AWS_SECRET = re.compile(
    r"\b(?:aws[_\s-]?)?(?:secret[_\s-]?)?access[_\s-]?key\b.{0,24}?"
    r"\b(?P<value>[A-Za-z0-9/+=]{40})\b",
    re.IGNORECASE,
)
_JWT = re.compile(r"\beyJ[a-zA-Z0-9_\-]+=*\.[a-zA-Z0-9_\-]+=*\.[a-zA-Z0-9_\-]+=*\b")
# The whole PEM block when its END line follows within 16 KiB, the BEGIN line
# otherwise. The bound keeps many BEGIN lines without an END from costing
# quadratic time.
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"
    r"(?:.{0,16384}?-----END (?:[A-Z]+ )*PRIVATE KEY-----)?",
    re.DOTALL,
)


def _name_detector() -> Detector:
    spacy_detector = SpacyNERDetector()
    return spacy_detector if spacy_detector.available else GazetteerNameDetector()


def default_detector_specs(
    *,
    phone_regions: Iterable[str] = (),
    detect_names: bool = True,
) -> tuple[DetectorSpec, ...]:
    """The built-in detector set.

    ``phone_regions`` are ISO country codes (``"EE"``, ``"GB"``) for local phone
    numbers without a ``+`` prefix. ``detect_names`` turns the person-name
    detector on or off; it uses spaCy when available and the ``names`` package
    otherwise, and does nothing when neither is installed.
    """
    return _build_default_specs(
        tuple(r.strip().upper() for r in phone_regions if r.strip()), detect_names
    )


@functools.lru_cache(maxsize=8)
def _build_default_specs(
    phone_regions: tuple[str, ...], detect_names: bool
) -> tuple[DetectorSpec, ...]:
    pii = RegexDetector(
        name="pii",
        patterns=[
            ("email", _EMAIL),
            ("address", _ADDRESS),
            ("credit_card", _CARD),
        ],
        validators={"credit_card": _luhn_valid},
    )
    national_ids = RegexDetector(
        name="pii",
        patterns=[("us_ssn", _SSN), ("estonian_personal_code", _ESTONIAN_CODE)],
        validators={"estonian_personal_code": _estonian_personal_code_valid},
    )
    secrets = RegexDetector(
        name="secret",
        patterns=[
            ("github_pat", _GITHUB_PAT),
            ("openai_api_key", _OPENAI_KEY),
            ("aws_access_key_id", _AWS_ACCESS_KEY_ID),
            ("aws_secret_access_key", _AWS_SECRET),
            ("jwt", _JWT),
            ("private_key", _PRIVATE_KEY),
        ],
    )

    specs = [
        DetectorSpec(secrets, DetectorFailureMode.FAIL_CLOSED),
        DetectorSpec(pii, DetectorFailureMode.FAIL_CLOSED),
        DetectorSpec(IbanDetector(), DetectorFailureMode.FAIL_CLOSED),
        DetectorSpec(national_ids, DetectorFailureMode.FAIL_CLOSED),
        DetectorSpec(PhoneNumberDetector(phone_regions), DetectorFailureMode.FAIL_OPEN),
    ]
    if detect_names:
        specs.append(DetectorSpec(_name_detector(), DetectorFailureMode.FAIL_OPEN))
    return tuple(specs)
