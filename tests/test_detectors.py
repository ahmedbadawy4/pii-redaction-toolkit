from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from piikit import (
    DetectorFailureMode,
    DetectorSpec,
    Finding,
    GazetteerNameDetector,
    IbanDetector,
    PhoneNumberDetector,
    RegexDetector,
    SpacyNERDetector,
    default_detector_specs,
    run_detectors,
)
from piikit.detectors import (
    _estonian_personal_code_valid,
    _iban_valid,
    _luhn_valid,
    _normalize_for_detection,
)
from piikit.models import DETECTOR_ERROR


class BrokenDetector:
    name = "broken_detector"

    def detect(self, text: str):
        raise RuntimeError("boom")


def _labels(text: str, specs=None) -> set[str]:
    specs = default_detector_specs() if specs is None else specs
    return {f.label for f in run_detectors(text, specs)}


# --- registry and failure modes ----------------------------------------------


def test_default_registry_declares_failure_modes():
    specs = default_detector_specs()

    assert specs
    assert all(isinstance(s.failure_mode, DetectorFailureMode) for s in specs)
    assert any(
        s.detector.name == "secret"
        and s.failure_mode == DetectorFailureMode.FAIL_CLOSED
        for s in specs
    )


def test_fail_closed_detector_failure_emits_detector_error():
    findings = run_detectors(
        "hello",
        [DetectorSpec(BrokenDetector(), DetectorFailureMode.FAIL_CLOSED)],
    )

    assert [(f.type, f.label) for f in findings] == [
        (DETECTOR_ERROR, "broken_detector")
    ]


def test_fail_open_detector_failure_is_suppressed():
    findings = run_detectors(
        "hello",
        [DetectorSpec(BrokenDetector(), DetectorFailureMode.FAIL_OPEN)],
    )

    assert findings == []


def test_a_crashing_detector_does_not_stop_the_others():
    email = RegexDetector("pii", [("email", re.compile(r"\S+@\S+"))])
    findings = run_detectors(
        "a@b.co",
        [
            DetectorSpec(BrokenDetector(), DetectorFailureMode.FAIL_OPEN),
            DetectorSpec(email),
        ],
    )

    assert [f.label for f in findings] == ["email"]


def test_disabled_spec_is_skipped():
    email = RegexDetector("pii", [("email", re.compile(r"\S+@\S+"))])

    assert run_detectors("a@b.co", [DetectorSpec(email, enabled=False)]) == []


def test_phone_regions_accepts_any_iterable_and_normalises_case():
    first = default_detector_specs(phone_regions=["ee", " gb "])
    second = default_detector_specs(phone_regions=("EE", "GB"))

    assert first is second


def test_detect_names_false_drops_the_name_detector():
    with_names = default_detector_specs()
    without_names = default_detector_specs(detect_names=False)

    assert len(without_names) == len(with_names) - 1


# --- checksum validators ------------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        ("4111 1111 1111 1111", True),
        ("5500000000000004", True),
        ("4111 1111 1111 1112", False),
        ("411111111111", False),  # 12 digits, too short
        ("41111111111111111111", False),  # 20 digits, too long
    ],
)
def test_luhn(value, expected):
    assert _luhn_valid(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("GB29NWBK60161331926819", True),
        ("GB29 NWBK 6016 1331 9268 19", True),
        ("DE89370400440532013000", True),
        ("EE382200221020145685", True),
        ("GB00ZZZZ00000000000000", False),
        ("GB29NWBK60161331926818", False),
        ("SHORT", False),
    ],
)
def test_iban(value, expected):
    assert _iban_valid(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("37605030299", True),
        ("37605030298", False),
        ("3760503029", False),
        ("376050302990", False),
    ],
)
def test_estonian_personal_code(value, expected):
    assert _estonian_personal_code_valid(value) is expected


# --- IBAN detector -----------------------------------------------------------


@pytest.mark.parametrize(
    "text, expected",
    [
        ("pay GB29NWBK60161331926819 today", "GB29NWBK60161331926819"),
        ("pay GB29 NWBK 6016 1331 9268 19 today", "GB29 NWBK 6016 1331 9268 19"),
        ("IBAN: DE89 3704 0044 0532 0130 00.", "DE89 3704 0044 0532 0130 00"),
        # Uppercase words after the number must not spoil the match.
        ("GB29 NWBK 6016 1331 9268 19 FOR THE TRANSFER", "GB29 NWBK 6016 1331 9268 19"),
        ("EE38 2200 2210 2014 5685 THIS", "EE38 2200 2210 2014 5685"),
        ("EE382200221020145685 THIS", "EE382200221020145685"),
    ],
)
def test_iban_found_with_exact_span(text, expected):
    [finding] = IbanDetector().detect(text)

    assert text[finding.span_start : finding.span_end] == expected


@pytest.mark.parametrize(
    "text",
    [
        "GB29NWBK60161331926818",  # wrong check digits
        "GB00ZZZZ00000000000000",  # right shape, fails mod-97
        "GB29NWBK60161331926819abc",  # runs into lowercase letters
        "xGB29NWBK60161331926819",  # not at a word boundary
        "GB29 NWBK 6016",  # too short
    ],
)
def test_iban_not_flagged(text):
    assert IbanDetector().detect(text) == []


def test_two_ibans_in_one_text():
    text = "from GB29NWBK60161331926819 to DE89 3704 0044 0532 0130 00 ok"

    assert len(IbanDetector().detect(text)) == 2


# --- evasion folding and span mapping ----------------------------------------


def test_spans_point_at_the_original_text_after_folding():
    token = "sk-" + "​".join(["a"] * 30)
    text = f"key: {token} end"

    [finding] = [f for f in run_detectors(text, default_detector_specs())]

    assert finding.label == "openai_api_key"
    assert text[finding.span_start : finding.span_end] == token


def test_homoglyph_email_is_found_and_the_span_covers_the_original():
    email = "jаne@example.com"  # Cyrillic a
    text = f"write to {email} now"

    [finding] = run_detectors(text, default_detector_specs(detect_names=False))

    assert finding.label == "email"
    assert text[finding.span_start : finding.span_end] == email


def test_fullwidth_digits_fold_to_ascii():
    folded, index_map = _normalize_for_detection("４１１１")

    assert folded == "4111"
    assert index_map == [0, 1, 2, 3]


def test_combining_marks_and_format_characters_are_dropped():
    folded, index_map = _normalize_for_detection("é​x")

    assert folded == "ex"
    assert index_map == [0, 3]


# --- regex detector -----------------------------------------------------------


def test_value_group_limits_the_reported_span():
    detector = RegexDetector(
        "secret",
        [("token", re.compile(r"token=(?P<value>\w+)"))],
    )

    [finding] = detector.detect("auth token=abc123 ok")

    assert (finding.span_start, finding.span_end) == (11, 17)


def test_validator_receives_the_value_and_can_reject_it():
    seen: list[str] = []

    def reject(value: str) -> bool:
        seen.append(value)
        return False

    detector = RegexDetector(
        "secret",
        [("token", re.compile(r"token=(?P<value>\w+)"))],
        validators={"token": reject},
    )

    assert detector.detect("token=abc123") == []
    assert seen == ["abc123"]


# --- optional detectors --------------------------------------------------------


def test_phone_international_number_is_found():
    pytest.importorskip("phonenumbers")
    text = "call +372 5340 7772 tomorrow"

    [finding] = PhoneNumberDetector().detect(text)

    assert finding.label == "phone"
    assert text[finding.span_start : finding.span_end] == "+372 5340 7772"


def test_phone_local_number_needs_a_region():
    pytest.importorskip("phonenumbers")
    text = "call 5340 7772 tomorrow"

    assert PhoneNumberDetector().detect(text) == []
    assert len(PhoneNumberDetector(regions=("EE",)).detect(text)) == 1


def test_phone_detector_reports_when_the_package_is_missing(monkeypatch):
    monkeypatch.setattr("importlib.util.find_spec", lambda name: None)
    detector = PhoneNumberDetector()

    assert detector.available is False
    assert detector.detect("+372 5340 7772") == []


def test_spacy_detector_keeps_only_person_entities():
    def fake_nlp(text: str):
        return SimpleNamespace(
            ents=[
                SimpleNamespace(start_char=0, end_char=5, label_="PERSON"),
                SimpleNamespace(start_char=9, end_char=15, label_="GPE"),
            ]
        )

    detector = SpacyNERDetector(nlp=fake_nlp)

    assert detector.available is True
    assert detector.detect("Alice from Tallinn") == [
        Finding("pii", "person_name", 0, 5, 0.85)
    ]


def test_spacy_detector_without_a_model_does_nothing():
    detector = SpacyNERDetector(nlp=None)
    detector._nlp = None  # force the "no model" path whatever is installed

    assert detector.available is False
    assert detector.detect("Alice Smith") == []


def test_gazetteer_finds_a_first_and_last_name_together():
    pytest.importorskip("names")
    detector = GazetteerNameDetector()
    text = "Meeting with John Smith about the budget."

    [finding] = detector.detect(text)

    assert finding.label == "person_name"
    assert text[finding.span_start : finding.span_end] == "John Smith"


def test_gazetteer_ignores_capitalised_words_that_are_not_names():
    pytest.importorskip("names")

    assert GazetteerNameDetector().detect("Quarterly Budget Review Meeting") == []
