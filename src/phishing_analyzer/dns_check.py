from __future__ import annotations

from .models import AuthVerdict, Indicator, ParsedEmail, Severity


def _txt(name: str) -> list[str]:
    import dns.resolver

    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
    except Exception:
        return []
    records: list[str] = []
    for answer in answers:
        try:
            records.append(b"".join(answer.strings).decode("utf-8", errors="replace"))
        except AttributeError:
            records.append(answer.to_text().strip('"'))
    return records


def dns_findings(email: ParsedEmail, verdict: AuthVerdict, selector: str) -> list[Indicator]:
    domain = email.from_domain
    if not domain:
        return []

    findings: list[Indicator] = []

    spf_records = [r for r in _txt(domain) if r.lower().startswith("v=spf1")]
    if not spf_records:
        findings.append(Indicator("dns", Severity.MEDIUM, domain, "Domain publishes no SPF record"))

    dmarc_records = [r for r in _txt("_dmarc." + domain) if r.lower().startswith("v=dmarc1")]
    if not dmarc_records:
        findings.append(Indicator("dns", Severity.MEDIUM, domain, "Domain publishes no DMARC record"))
    else:
        record = dmarc_records[0].lower()
        policy = ""
        for tag in record.split(";"):
            tag = tag.strip()
            if tag.startswith("p="):
                policy = tag[2:].strip()
                break
        verdict.dmarc_policy = policy or verdict.dmarc_policy
        if policy == "none":
            findings.append(
                Indicator("dns", Severity.LOW, domain, "DMARC policy is p=none, so failures are only reported, not blocked")
            )

    if selector and verdict.dkim != "pass":
        key_host = f"{selector}._domainkey.{domain}"
        if not _txt(key_host):
            findings.append(Indicator("dns", Severity.LOW, key_host, "No DKIM public key published at the selector in the signature"))

    return findings
