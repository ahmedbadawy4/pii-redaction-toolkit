"""Scan a text and replace what the detectors found."""

from __future__ import annotations

import re
from bisect import bisect_left
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from .detectors import DetectorSpec, default_detector_specs, run_detectors
from .models import DETECTOR_ERROR, Finding


class Style(StrEnum):
    """How a finding is replaced.

    ``LABEL`` gives ``[EMAIL]``. ``MASK`` gives one mask character per replaced
    character, which keeps the length (and so leaks it). ``TOKEN`` gives
    ``<EMAIL_1>``, the same token for the same value, and ``Redaction.mapping``
    holds what each token stands for so :func:`restore` can undo it.
    """

    LABEL = "label"
    MASK = "mask"
    TOKEN = "token"


class DetectorFailure(RuntimeError):
    """A fail-closed detector crashed, so the scan may have missed something.

    ``redact`` raises this instead of returning text that might still contain
    personal data. ``detectors`` names the detectors that failed.
    """

    def __init__(self, detectors: Iterable[str]) -> None:
        self.detectors = tuple(detectors)
        super().__init__(f"detector failed: {', '.join(self.detectors)}")


@dataclass(frozen=True)
class Redaction:
    text: str
    findings: tuple[Finding, ...]
    mapping: dict[str, str] = field(default_factory=dict)


def resolve_overlaps(findings: Iterable[Finding]) -> list[Finding]:
    """Keep one finding wherever spans overlap, sorted by position.

    The winner has the higher confidence, then the longer span, then the earlier
    start. Zero-width findings are dropped.
    """
    ranked = sorted(
        (f for f in findings if f.length > 0),
        key=lambda f: (-f.confidence, -f.length, f.span_start),
    )
    kept: list[Finding] = []
    starts: list[int] = []
    for f in ranked:
        i = bisect_left(starts, f.span_start)
        if i > 0 and kept[i - 1].span_end > f.span_start:
            continue
        if i < len(kept) and kept[i].span_start < f.span_end:
            continue
        kept.insert(i, f)
        starts.insert(i, f.span_start)
    return kept


def scan(
    text: str,
    detector_specs: Iterable[DetectorSpec] | None = None,
    *,
    min_confidence: float = 0.0,
) -> list[Finding]:
    """Find personal data and secrets in ``text``.

    Returns non-overlapping findings sorted by position, spans relative to
    ``text``. If a fail-closed detector crashed, the result also holds a
    ``detector_error`` finding for it.
    """
    specs = default_detector_specs() if detector_specs is None else detector_specs
    raw = run_detectors(text, specs)
    errors = [f for f in raw if f.type == DETECTOR_ERROR]
    real = [f for f in raw if f.type != DETECTOR_ERROR]
    kept = [f for f in resolve_overlaps(real) if f.confidence >= min_confidence]
    return kept + errors


def redact(
    text: str,
    detector_specs: Iterable[DetectorSpec] | None = None,
    *,
    style: Style | str = Style.LABEL,
    min_confidence: float = 0.0,
    mask_char: str = "*",
) -> Redaction:
    """Replace everything the detectors find in ``text``.

    Raises :class:`DetectorFailure` if a fail-closed detector crashed.
    """
    style = Style(style)
    findings = scan(text, detector_specs, min_confidence=min_confidence)
    failed = [f.label for f in findings if f.type == DETECTOR_ERROR]
    if failed:
        raise DetectorFailure(failed)

    mapping: dict[str, str] = {}
    token_for: dict[tuple[str, str], str] = {}
    counts: dict[str, int] = {}
    out: list[str] = []
    cursor = 0
    for f in findings:
        out.append(text[cursor : f.span_start])
        original = text[f.span_start : f.span_end]
        if style is Style.LABEL:
            out.append(f"[{f.label.upper()}]")
        elif style is Style.MASK:
            out.append(mask_char * len(original))
        else:
            key = (f.label, original)
            if key not in token_for:
                counts[f.label] = counts.get(f.label, 0) + 1
                token_for[key] = f"<{f.label.upper()}_{counts[f.label]}>"
                mapping[token_for[key]] = original
            out.append(token_for[key])
        cursor = f.span_end
    out.append(text[cursor:])
    return Redaction(text="".join(out), findings=tuple(findings), mapping=mapping)


def restore(text: str, mapping: Mapping[str, str]) -> str:
    """Put the original values back for tokens made by ``Style.TOKEN``.

    Tokens are replaced in one pass, so a restored value that looks like a token
    is not replaced again. Only use it on text that came from ``redact``: a token
    that was already in the input text cannot be told apart from one ``redact``
    made.
    """
    if not mapping:
        return text
    pattern = re.compile("|".join(re.escape(t) for t in mapping))
    return pattern.sub(lambda m: mapping[m.group(0)], text)
