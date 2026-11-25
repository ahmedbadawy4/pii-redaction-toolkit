from __future__ import annotations

from dataclasses import dataclass

# Type used for the marker a fail-closed detector emits when it crashes.
# It is not a real detection: its span is (0, 0).
DETECTOR_ERROR = "detector_error"


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing a detector found in a text.

    ``type`` is the category (``pii`` or ``secret``), ``label`` the specific
    kind (``email``, ``iban``, ``github_pat`` ...). ``span_start`` and
    ``span_end`` are character offsets into the original text, end exclusive.
    ``confidence`` runs from 0 to 1; pattern detectors with a checksum report 1.
    """

    type: str
    label: str
    span_start: int
    span_end: int
    confidence: float = 1.0

    @property
    def length(self) -> int:
        return self.span_end - self.span_start
