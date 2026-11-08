from __future__ import annotations

from pathlib import Path

import pytest

from phishing_analyzer.analyze import analyze_file
from phishing_analyzer.models import Severity

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

EXPECTED = {
    "malicious-bec-ceo-spoof.eml": "malicious",
    "malicious-brand-lookalike.eml": "malicious",
    "malicious-docusign-punycode.eml": "malicious",
    "malicious-invoice-archive.eml": "malicious",
    "malicious-mfa-shortener.eml": "malicious",
    "risky-forwarded-quote.eml": "suspicious",
    "risky-macro-attachment.eml": "suspicious",
    "risky-vendor-payment-change.eml": "suspicious",
    "safe-internal-no-auth.eml": "clean",
    "safe-newsletter.eml": "clean",
    "safe-partner-invoice.eml": "clean",
    "safe-password-reset.eml": "clean",
}

BAND = {"malicious": "malicious", "risky": "suspicious", "safe": "clean"}


def corpus_files() -> list[Path]:
    return sorted(SAMPLES.glob("*.eml"))


def test_corpus_matches_manifest():
    names = {p.name for p in corpus_files()}
    assert names == set(EXPECTED), f"corpus drift: {names ^ set(EXPECTED)}"


@pytest.mark.parametrize("filename,verdict", sorted(EXPECTED.items()))
def test_expected_verdict(filename, verdict):
    result = analyze_file(SAMPLES / filename)
    assert result.verdict == verdict, f"{filename}: got {result.verdict} at score {result.score}"


@pytest.mark.parametrize("path", corpus_files(), ids=lambda p: p.name)
def test_filename_band_matches_verdict(path):
    band = path.name.split("-", 1)[0]
    result = analyze_file(path)
    assert BAND[band] == result.verdict


@pytest.mark.parametrize("path", corpus_files(), ids=lambda p: p.name)
def test_malicious_messages_have_a_high_indicator(path):
    if not path.name.startswith("malicious-"):
        pytest.skip("only malicious samples")
    result = analyze_file(path)
    assert any(i.severity == Severity.HIGH for i in result.indicators)


@pytest.mark.parametrize("path", corpus_files(), ids=lambda p: p.name)
def test_safe_messages_have_no_high_indicators(path):
    if not path.name.startswith("safe-"):
        pytest.skip("only safe samples")
    result = analyze_file(path)
    assert not any(i.severity == Severity.HIGH for i in result.indicators)


def test_every_attachment_is_hashed():
    for path in corpus_files():
        result = analyze_file(path)
        for attachment in result.attachments:
            assert len(attachment.sha256) == 64
            assert attachment.size > 0
