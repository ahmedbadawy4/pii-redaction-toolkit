from __future__ import annotations

import re
import time

import pytest

from piikit import (
    DetectorFailure,
    DetectorFailureMode,
    DetectorSpec,
    Finding,
    RegexDetector,
    Style,
    default_detector_specs,
    redact,
    resolve_overlaps,
    restore,
    scan,
)
from piikit.models import DETECTOR_ERROR

SPECS = default_detector_specs(detect_names=False)

SAMPLE = (
    "Mail jane.doe@example.com or bob@example.org, card 4111 1111 1111 1111, "
    "IBAN GB29NWBK60161331926819."
)


class BrokenDetector:
    name = "broken_detector"

    def detect(self, text: str):
        raise RuntimeError("boom")


# --- styles ---------------------------------------------------------------------


def test_label_style_names_each_kind():
    result = redact(SAMPLE, SPECS)

    assert result.text == "Mail [EMAIL] or [EMAIL], card [CREDIT_CARD], IBAN [IBAN]."


def test_mask_style_keeps_the_length_of_each_value():
    result = redact("mail jane.doe@example.com now", SPECS, style=Style.MASK)

    assert result.text == "mail " + "*" * len("jane.doe@example.com") + " now"


def test_mask_character_can_be_changed():
    result = redact("a@b.co", SPECS, style="mask", mask_char="#")

    assert result.text == "######"


def test_token_style_reuses_a_token_for_the_same_value():
    text = "a@b.co wrote to c@d.org and then to a@b.co again"

    result = redact(text, SPECS, style=Style.TOKEN)

    assert result.text == "<EMAIL_1> wrote to <EMAIL_2> and then to <EMAIL_1> again"
    assert result.mapping == {"<EMAIL_1>": "a@b.co", "<EMAIL_2>": "c@d.org"}


def test_token_round_trip_restores_the_original_text():
    result = redact(SAMPLE, SPECS, style=Style.TOKEN)

    assert result.text != SAMPLE
    assert restore(result.text, result.mapping) == SAMPLE


def test_restore_does_not_replace_inside_restored_values():
    mapping = {"<EMAIL_1>": "<EMAIL_2>", "<EMAIL_2>": "x"}

    assert restore("<EMAIL_1> <EMAIL_2>", mapping) == "<EMAIL_2> x"


def test_restore_without_a_mapping_returns_the_text():
    assert restore("unchanged", {}) == "unchanged"


def test_unknown_style_is_rejected():
    with pytest.raises(ValueError):
        redact("a@b.co", SPECS, style="shout")


def test_text_without_findings_is_returned_unchanged():
    result = redact("nothing to see here", SPECS)

    assert result.text == "nothing to see here"
    assert result.findings == ()


def test_redacted_text_contains_none_of_the_original_values():
    result = redact(SAMPLE, SPECS)

    for value in ("jane.doe@example.com", "bob@example.org", "4111", "GB29NWBK"):
        assert value not in result.text


# --- spans on tricky text --------------------------------------------------------


def test_zero_width_characters_inside_a_secret_are_removed_with_it():
    token = "sk-" + "​".join(["a"] * 30)

    result = redact(f"key: {token} end", SPECS)

    assert result.text == "key: [OPENAI_API_KEY] end"


def test_a_pem_block_is_removed_as_a_whole():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----"
    )

    result = redact(f"before\n{pem}\nafter", SPECS)

    assert result.text == "before\n[PRIVATE_KEY]\nafter"


def test_only_the_aws_secret_value_is_replaced_not_the_words_before_it():
    result = redact("aws secret access key: " + "A" * 40 + " end", SPECS)

    assert result.text == "aws secret access key: [AWS_SECRET_ACCESS_KEY] end"


# --- scan and overlaps -----------------------------------------------------------


def test_scan_returns_findings_sorted_by_position():
    findings = scan(SAMPLE, SPECS)

    starts = [f.span_start for f in findings]
    assert starts == sorted(starts)
    assert [f.label for f in findings] == ["email", "email", "credit_card", "iban"]


def test_overlap_is_won_by_higher_confidence_then_longer_span():
    low = Finding("pii", "phone", 0, 10, 0.9)
    high = Finding("pii", "credit_card", 2, 8, 1.0)
    same_long = Finding("pii", "a", 20, 30, 1.0)
    same_short = Finding("pii", "b", 22, 28, 1.0)

    kept = resolve_overlaps([low, high, same_short, same_long])

    assert [f.label for f in kept] == ["credit_card", "a"]


def test_touching_spans_are_both_kept():
    first = Finding("pii", "a", 0, 5)
    second = Finding("pii", "b", 5, 9)

    assert resolve_overlaps([second, first]) == [first, second]


def test_zero_width_findings_are_dropped_by_overlap_resolution():
    assert resolve_overlaps([Finding("pii", "a", 3, 3)]) == []


def test_overlap_resolution_handles_many_findings_quickly():
    findings = [Finding("pii", "a", i * 10, i * 10 + 5) for i in range(20000)]

    started = time.perf_counter()
    kept = resolve_overlaps(findings)
    elapsed = time.perf_counter() - started

    assert len(kept) == 20000
    assert elapsed < 2.0


def test_min_confidence_filters_weak_findings():
    weak = RegexDetector("pii", [("guess", re.compile(r"foo"))], confidence=0.5)
    strong = RegexDetector("pii", [("sure", re.compile(r"bar"))], confidence=0.95)
    specs = [DetectorSpec(weak), DetectorSpec(strong)]

    assert [f.label for f in scan("foo bar", specs)] == ["guess", "sure"]
    assert [f.label for f in scan("foo bar", specs, min_confidence=0.9)] == ["sure"]


# --- failure handling ------------------------------------------------------------


def test_scan_reports_a_fail_closed_crash_as_a_detector_error():
    specs = [DetectorSpec(BrokenDetector(), DetectorFailureMode.FAIL_CLOSED)]

    findings = scan("hello", specs)

    assert [(f.type, f.label) for f in findings] == [
        (DETECTOR_ERROR, "broken_detector")
    ]


def test_redact_refuses_to_return_text_after_a_fail_closed_crash():
    specs = [DetectorSpec(BrokenDetector(), DetectorFailureMode.FAIL_CLOSED)]

    with pytest.raises(DetectorFailure) as raised:
        redact("hello a@b.co", specs)

    assert raised.value.detectors == ("broken_detector",)


def test_redact_goes_on_after_a_fail_open_crash():
    specs = [
        DetectorSpec(BrokenDetector(), DetectorFailureMode.FAIL_OPEN),
        *SPECS,
    ]

    assert redact("a@b.co", specs).text == "[EMAIL]"
