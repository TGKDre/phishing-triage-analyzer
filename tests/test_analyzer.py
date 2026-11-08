from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from phishing_analyzer.analyze import analyze_file, score_findings
from phishing_analyzer.auth import aligns, auth_findings, parse_auth
from phishing_analyzer.cli import main
from phishing_analyzer.indicators import defang, extract_urls, levenshtein, registrable
from phishing_analyzer.models import Indicator, Severity
from phishing_analyzer.parse import parse_eml
from phishing_analyzer.report import write_csv, write_html

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
NOW = datetime(2026, 11, 6, tzinfo=timezone.utc)


def test_parses_headers_and_bodies():
    email = parse_eml(SAMPLES / "safe-newsletter.eml")
    assert email.subject == "November product update"
    assert email.from_addr == "news@example.com"
    assert email.from_domain == "example.com"
    assert email.return_path == "bounce@example.com"
    assert "https://example.com/updates/november" in email.text_body


def test_auth_results_parsed_from_headers():
    email = parse_eml(SAMPLES / "malicious-bec-ceo-spoof.eml")
    verdict = parse_auth(email)
    assert verdict.spf == "fail"
    assert verdict.dkim == "none"
    assert verdict.dmarc == "fail"
    assert verdict.dmarc_domain == "example.com"
    assert verdict.spf_domain == "mail-relay.example"


def test_received_spf_fallback():
    email = parse_eml(SAMPLES / "safe-internal-no-auth.eml")
    email.received_spf = ["Pass (mailfrom) identity=mailfrom; client-ip=192.0.2.10; envelope-from=it@example.org"]
    verdict = parse_auth(email)
    assert verdict.spf == "pass"


def test_alignment_helper():
    assert aligns("example.com", "example.com")
    assert aligns("mail.example.com", "example.com")
    assert not aligns("example.com", "example.net")


def test_dmarc_fail_creates_high_finding():
    email = parse_eml(SAMPLES / "malicious-bec-ceo-spoof.eml")
    findings = auth_findings(email, parse_auth(email))
    assert any(f.severity == Severity.HIGH and "DMARC" in f.detail for f in findings)


def test_clean_message_has_no_findings():
    result = analyze_file(SAMPLES / "safe-newsletter.eml")
    assert result.indicators == []
    assert result.verdict == "clean"
    assert result.score == 0


def test_bec_is_malicious_with_attachment_hash():
    result = analyze_file(SAMPLES / "malicious-bec-ceo-spoof.eml")
    assert result.verdict == "malicious"
    assert result.attachments[0].filename == "invoice.pdf.exe"
    assert len(result.attachments[0].sha256) == 64
    assert any("Double extension" in f.detail for f in result.indicators)
    assert any("Replies go to" in f.detail for f in result.indicators)


def test_lookalike_domain_and_ip_url_are_high():
    result = analyze_file(SAMPLES / "malicious-brand-lookalike.eml")
    assert result.verdict == "malicious"
    details = " ".join(f.detail for f in result.indicators)
    assert "imitates microsoft" in details
    assert "raw IP address" in details


def test_macro_attachment_is_suspicious():
    result = analyze_file(SAMPLES / "risky-macro-attachment.eml")
    assert result.verdict == "suspicious"
    assert any("Macro-enabled" in f.detail for f in result.indicators)


def test_message_without_auth_headers_is_clean_but_flagged_low():
    result = analyze_file(SAMPLES / "safe-internal-no-auth.eml")
    assert result.verdict == "clean"
    assert all(f.severity == Severity.LOW for f in result.indicators)


def test_scoring_thresholds():
    high = [Indicator("x", Severity.HIGH, "v", "d")]
    medium = [Indicator("x", Severity.MEDIUM, "v", "d")]
    low = [Indicator("x", Severity.LOW, "v", "d")]
    assert score_findings(high) == (40, "suspicious")
    assert score_findings(high + medium + medium) == (70, "malicious")
    assert score_findings(medium) == (15, "clean")
    assert score_findings(low * 4) == (20, "suspicious")


def test_url_extraction_and_defanging():
    urls = extract_urls("see https://a.example/login and http://198.51.100.7/x", "<a href='https://b.example/y'>y</a>")
    assert "https://a.example/login" in urls
    assert "https://b.example/y" in urls
    assert len(urls) == len(set(urls))
    assert defang("https://a.example/x") == "hxxps://a[.]example/x"


def test_domain_helpers():
    assert registrable("mail.example.co.uk") == "example.co.uk"
    assert registrable("a.b.example.com") == "example.com"
    assert levenshtein("example", "examp1e") == 1


def test_reports_are_written(tmp_path):
    results = [analyze_file(SAMPLES / "malicious-bec-ceo-spoof.eml")]
    csv_path = write_csv(results, tmp_path / "findings.csv")
    html_path = write_html(results, tmp_path / "report.html")
    header = csv_path.read_text(encoding="utf-8").splitlines()[0]
    assert header.startswith("file,verdict,score")
    page = html_path.read_text(encoding="utf-8")
    assert "Phishing triage report" in page
    assert "invoice.pdf.exe" in page


def test_cli_end_to_end(tmp_path):
    code = main(["--input", str(SAMPLES), "--out", str(tmp_path), "--json", "--fail-on", "malicious"])
    assert code == 2
    assert (tmp_path / "findings.csv").exists()
    assert (tmp_path / "report.html").exists()
    assert (tmp_path / "results.json").exists()


def test_cli_clean_exit_code(tmp_path):
    assert main(["--input", str(SAMPLES / "safe-newsletter.eml"), "--out", str(tmp_path), "--fail-on", "malicious"]) == 0
