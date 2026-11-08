from __future__ import annotations

import json

from .auth import auth_findings, dkim_selector, parse_auth
from .indicators import attachment_findings, display_name_findings, sender_domain_findings, url_findings
from .models import Analysis, Indicator, Severity
from .parse import parse_eml

WEIGHTS = {Severity.HIGH: 40, Severity.MEDIUM: 15, Severity.LOW: 5}
ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


def score_findings(findings: list[Indicator]) -> tuple[int, str]:
    total = sum(WEIGHTS.get(f.severity, 0) for f in findings)
    if total >= 60:
        return total, "malicious"
    if total >= 20:
        return total, "suspicious"
    return total, "clean"


def _reason(f: Indicator) -> str:
    return f"{f.severity}: {f.detail}"


def analyze_file(path, dns: bool = False) -> Analysis:
    email = parse_eml(path)
    auth = parse_auth(email)

    findings: list[Indicator] = []
    findings.extend(auth_findings(email, auth))
    url_hits, _ = url_findings(email)
    findings.extend(url_hits)
    findings.extend(attachment_findings(email))
    findings.extend(display_name_findings(email))
    findings.extend(sender_domain_findings(email))

    if dns:
        from .dns_check import dns_findings

        findings.extend(dns_findings(email, auth, dkim_selector(email)))

    findings.sort(key=lambda f: ORDER.get(f.severity, 9))
    score, verdict = score_findings(findings)

    return Analysis(
        path=email.path,
        subject=email.subject,
        from_display=email.from_display,
        from_addr=email.from_addr,
        from_domain=email.from_domain,
        return_path=email.return_path,
        reply_to=email.reply_to,
        date=email.date,
        auth=auth,
        indicators=findings,
        attachments=email.attachments,
        score=score,
        verdict=verdict,
        reasons=[_reason(f) for f in findings[:8]],
    )


def analyze_many(paths, dns: bool = False) -> list[Analysis]:
    return [analyze_file(p, dns=dns) for p in paths]


def to_json(results: list[Analysis]) -> str:
    payload = [
        {
            "file": str(r.path),
            "verdict": r.verdict,
            "score": r.score,
            "subject": r.subject,
            "from": r.from_addr,
            "from_domain": r.from_domain,
            "return_path": r.return_path,
            "reply_to": r.reply_to,
            "auth": {
                "spf": r.auth.spf,
                "dkim": r.auth.dkim,
                "dmarc": r.auth.dmarc,
                "dmarc_domain": r.auth.dmarc_domain,
                "dmarc_policy": r.auth.dmarc_policy,
            },
            "indicators": [
                {"category": i.category, "severity": i.severity, "value": i.value, "detail": i.detail}
                for i in r.indicators
            ],
            "attachments": [
                {"filename": a.filename, "content_type": a.content_type, "size": a.size, "sha256": a.sha256}
                for a in r.attachments
            ],
        }
        for r in results
    ]
    return json.dumps(payload, indent=2)
