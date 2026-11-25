from __future__ import annotations

import io
import json

import pytest

from piikit import DetectorFailureMode, DetectorSpec
from piikit.__main__ import main


def _stdin(monkeypatch, text: str) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(text))


def test_redacts_standard_input(monkeypatch, capsys):
    _stdin(monkeypatch, "mail jane.doe@example.com\n")

    assert main([]) == 0
    assert capsys.readouterr().out == "mail [EMAIL]\n"


def test_reads_a_file_and_masks(tmp_path, capsys):
    path = tmp_path / "in.txt"
    path.write_text("a@b.co", encoding="utf-8")

    assert main(["--style", "mask", str(path)]) == 0
    assert capsys.readouterr().out == "******"


def test_findings_are_json_without_the_values(monkeypatch, capsys):
    _stdin(monkeypatch, "mail jane.doe@example.com")

    assert main(["--findings"]) == 0
    out = capsys.readouterr().out
    [item] = json.loads(out)

    assert item == {
        "type": "pii",
        "label": "email",
        "start": 5,
        "end": 25,
        "confidence": 1.0,
    }
    assert "jane.doe" not in out


def test_token_style_is_not_offered_on_the_command_line(monkeypatch):
    _stdin(monkeypatch, "x")

    with pytest.raises(SystemExit) as raised:
        main(["--style", "token"])

    assert raised.value.code == 2


def test_a_crashed_detector_gives_exit_code_2_and_no_output(monkeypatch, capsys):
    class Broken:
        name = "broken_detector"

        def detect(self, text: str):
            raise RuntimeError("boom")

    monkeypatch.setattr(
        "piikit.__main__.default_detector_specs",
        lambda **_: [DetectorSpec(Broken(), DetectorFailureMode.FAIL_CLOSED)],
    )
    _stdin(monkeypatch, "a@b.co")

    assert main([]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "broken_detector" in captured.err
