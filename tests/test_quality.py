"""Detector quality: recall and precision on a labelled corpus, evasion,
Unicode edge cases and a latency bound.

The corpus measures current behaviour instead of asserting one hand-picked
example per detector (``test_detectors.py`` does that). It is a regression
guard, not a benchmark: it catches a detector that silently stops working or
starts matching look-alikes.
"""

from __future__ import annotations

import time

import pytest

from piikit import default_detector_specs, scan

# Names and phones depend on optional packages; the corpus is about the
# pattern detectors, so these two labels are ignored on the negative side.
OPTIONAL_LABELS = {"person_name", "phone"}


def _labels(text: str) -> set[str]:
    return {f.label for f in scan(text, default_detector_specs(detect_names=False))}


def _pem(kind: str, body: str) -> str:
    # Built from parts so that a secret scanner does not flag this file.
    dashes = "-" * 5
    return f"{dashes}BEGIN {kind}{dashes}\n{body}\n{dashes}END {kind}{dashes}"


POSITIVE_SAMPLES = [
    ("4111 1111 1111 1111 is my card number", "credit_card"),
    ("4111-1111-1111-1111 on file", "credit_card"),
    ("card: 5500000000000004 exp 12/29", "credit_card"),
    ("SSN 219-09-9999 on the form", "us_ssn"),
    ("ssn 219099999", "us_ssn"),
    ("IBAN GB29NWBK60161331926819 for the transfer", "iban"),
    ("IBAN DE89 3704 0044 0532 0130 00 please", "iban"),
    ("My Estonian personal code is 37605030299", "estonian_personal_code"),
    ("contact me at jane.doe@example.com please", "email"),
    ("token ghp_" + "a" * 36, "github_pat"),
    ("key sk-" + "a" * 40, "openai_api_key"),
    # Built from two parts so that a secret scanner does not flag this file.
    ("AKIA" + "ABCDEFGHIJKLMNOP" + " is the access key id", "aws_access_key_id"),
    ("aws secret access key: " + "A" * 40, "aws_secret_access_key"),
    (
        ".".join(
            [
                "eyJhbGciOiJIUzI1NiJ9",
                "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
                "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            ]
        ),
        "jwt",
    ),
    (_pem("RSA PRIVATE KEY", "MIIBOgIBAAJBAK"), "private_key"),
    (_pem("PRIVATE KEY", "abc"), "private_key"),
    ("lives at 221 Baker Street", "address"),
]

NEGATIVE_SAMPLES = [
    # Fails Luhn.
    "4111 1111 1111 1112 is not a real card",
    "order number 1234567890123456 was shipped",
    # Invalid SSN prefixes (666 and 900-999 are excluded on purpose).
    "reference id 900-12-3456 is not a taxpayer id",
    "reference id 666-12-3456 is not a taxpayer id",
    # IBAN-shaped but fails mod-97.
    "account code GB00ZZZZ00000000000000 is invalid",
    # Estonian code shape with a wrong check digit.
    "reference 37605030298 is not valid",
    # Mentions secrets in prose without a value.
    "please reset your password and rotate the api key when convenient",
    # A number followed by words, but no street type.
    "we shipped 40 large boxes yesterday",
    # Too short to be a key.
    "the prefix sk-test is only a prefix",
]


@pytest.mark.parametrize("text, expected_label", POSITIVE_SAMPLES)
def test_recall_detects_known_positive_signatures(text, expected_label):
    assert expected_label in _labels(text), f"expected {expected_label!r} in {text!r}"


@pytest.mark.parametrize("text", NEGATIVE_SAMPLES)
def test_precision_does_not_flag_structural_lookalikes(text):
    unexpected = _labels(text) - OPTIONAL_LABELS
    assert not unexpected, f"unexpected findings {unexpected} for {text!r}"


def test_measured_recall_and_precision_clear_the_floor():
    hits = sum(1 for text, label in POSITIVE_SAMPLES if label in _labels(text))
    recall = hits / len(POSITIVE_SAMPLES)
    flagged = [t for t in NEGATIVE_SAMPLES if _labels(t) - OPTIONAL_LABELS]

    assert recall >= 0.95, f"recall {recall:.2f} is below the floor"
    assert not flagged, f"negative samples flagged: {flagged}"


# --- evasion --------------------------------------------------------------------


def test_extra_internal_whitespace_in_a_card_number():
    assert "credit_card" in _labels("4111  1111   1111 1111")


def test_mixed_separators_in_a_card_number():
    assert "credit_card" in _labels("4111-1111 1111-1111")


def test_zero_width_space_inside_a_secret():
    token = "sk-" + "​".join(["a"] * 40)
    assert "openai_api_key" in _labels(f"key: {token}")


def test_homoglyphs_inside_a_secret_prefix():
    # Cyrillic capital "А" (U+0410) in place of the fourth letter of "AKIA".
    assert "aws_access_key_id" in _labels("AKIАABCDEFGHIJKLMNOP")


# --- Unicode and fragmentation --------------------------------------------------


def test_email_with_combining_accents():
    # "jose" with a combining acute accent on the last e (NFD form).
    assert "email" in _labels("reach josé@example.com for support")


def test_email_inside_right_to_left_text():
    greeting = "مرحبًا"
    thanks = "شكرا"
    assert "email" in _labels(f"{greeting} contact test@example.com {thanks}")


def test_fullwidth_digit_card_number():
    # Fullwidth forms of the Luhn-valid test number 4111111111111111.
    fullwidth = "４１１１１１１１１１１１１１１１"
    assert "credit_card" in _labels(f"card {fullwidth} on file")


def test_secret_split_across_a_newline_is_not_joined():
    text = "ghp_" + "a" * 18 + "\n" + "a" * 18
    assert "github_pat" not in _labels(text)


# --- latency --------------------------------------------------------------------


def test_latency_on_a_large_payload():
    filler = (
        "The quick brown fox jumps over the lazy dog. " * 400
        + "contact jane.doe@example.com or call about invoice 1234567890123456. "
    ) * 5
    specs = default_detector_specs()

    started = time.perf_counter()
    scan(filler, specs)
    elapsed = time.perf_counter() - started

    assert elapsed < 5.0, f"scan took {elapsed:.2f}s on {len(filler)} characters"


def test_many_unterminated_private_key_headers_do_not_blow_up():
    text = "-----BEGIN PRIVATE KEY-----\nabc\n" * 3000
    specs = default_detector_specs(detect_names=False)

    started = time.perf_counter()
    scan(text, specs)
    elapsed = time.perf_counter() - started

    assert elapsed < 5.0, f"scan took {elapsed:.2f}s"
