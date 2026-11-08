from __future__ import annotations

import re

from .models import AuthVerdict, Indicator, ParsedEmail, Severity

_MECH = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy|bestguesspass)\b",
    re.IGNORECASE,
)
_DKIM_DOMAIN = re.compile(r"\bd\s*=\s*([^;\s]+)", re.IGNORECASE)
_DMARC_HEADER_FROM = re.compile(r"header\.from\s*=\s*([^\s;]+)", re.IGNORECASE)
_DMARC_POLICY = re.compile(r"\bp\s*=\s*([a-z]+)", re.IGNORECASE)
_RECEIVED_SPF = re.compile(r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE)
_SELECTOR = re.compile(r"\bs\s*=\s*([^;\s]+)", re.IGNORECASE)


def _set_once(verdict: AuthVerdict, mech: str, result: str, domain: str, source: str) -> None:
    current = getattr(verdict, mech)
    if current != "none":
        return
    setattr(verdict, mech, result)
    if mech == "spf":
        verdict.spf_domain = domain
    elif mech == "dkim":
        verdict.dkim_domain = domain
    else:
        verdict.dmarc_domain = domain
    if not verdict.source:
        verdict.source = source


def parse_auth(email: ParsedEmail) -> AuthVerdict:
    verdict = AuthVerdict()

    for header in email.auth_results:
        source = header.split(";", 1)[0].strip()
        for match in _MECH.finditer(header):
            mech = match.group(1).lower()
            result = match.group(2).lower()
            if mech == "dkim":
                dm = _DKIM_DOMAIN.search(header)
                domain = dm.group(1).strip().lower() if dm else ""
            elif mech == "dmarc":
                dm = _DMARC_HEADER_FROM.search(header)
                domain = dm.group(1).strip().lower() if dm else ""
                pm = _DMARC_POLICY.search(header)
                if pm and not verdict.dmarc_policy:
                    verdict.dmarc_policy = pm.group(1).lower()
            else:
                dm = re.search(r"smtp\.mailfrom\s*=\s*([^\s;]+)", header, re.IGNORECASE)
                domain = dm.group(1).strip().lower() if dm else ""
            _set_once(verdict, mech, result, domain, source)

    if verdict.spf == "none":
        for header in email.received_spf:
            match = _RECEIVED_SPF.match(header)
            if match:
                verdict.spf = match.group(1).lower()
                dm = re.search(r"(?:envelope-from|identity)\s*=?\s*[\w.@+-]*@([\w.-]+)", header, re.IGNORECASE)
                if dm:
                    verdict.spf_domain = dm.group(1).strip().lower()
                break

    if verdict.dkim == "none" and email.dkim_signatures:
        dm = _DKIM_DOMAIN.search(email.dkim_signatures[0])
        verdict.dkim_domain = dm.group(1).strip().lower() if dm else ""

    if not verdict.source:
        verdict.source = "headers"
    return verdict


def dkim_selector(email: ParsedEmail) -> str:
    if not email.dkim_signatures:
        return ""
    match = _SELECTOR.search(email.dkim_signatures[0])
    return match.group(1).strip() if match else ""


def aligns(sender_domain: str, authenticated_domain: str) -> bool:
    if not sender_domain or not authenticated_domain:
        return False
    a, b = sender_domain.lower(), authenticated_domain.lower()
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def auth_findings(email: ParsedEmail, verdict: AuthVerdict) -> list[Indicator]:
    findings: list[Indicator] = []
    spf, dkim, dmarc = verdict.spf, verdict.dkim, verdict.dmarc

    if dmarc in ("fail", "permerror"):
        findings.append(
            Indicator(
                "email_auth",
                Severity.HIGH,
                f"dmarc={dmarc}",
                f"DMARC failed for {verdict.dmarc_domain or email.from_domain or 'the sending domain'}",
            )
        )
    elif dmarc in ("none", ""):
        findings.append(
            Indicator(
                "email_auth",
                Severity.LOW,
                "dmarc=missing",
                "No DMARC result in the headers, so sender alignment cannot be confirmed from this message alone",
            )
        )
    elif dmarc == "pass" and verdict.dmarc_domain and not aligns(email.from_domain, verdict.dmarc_domain):
        findings.append(
            Indicator(
                "email_auth",
                Severity.HIGH,
                f"dmarc=pass header.from={verdict.dmarc_domain}",
                f"DMARC passed for {verdict.dmarc_domain} but the visible From domain is {email.from_domain}",
            )
        )

    if spf == "fail":
        findings.append(Indicator("email_auth", Severity.MEDIUM, "spf=fail", "Sending IP is not authorised by the domain's SPF record"))
    elif spf == "softfail":
        findings.append(Indicator("email_auth", Severity.MEDIUM, "spf=softfail", "Sending IP is outside the domain's SPF policy"))
    elif spf in ("temperror", "permerror"):
        findings.append(Indicator("email_auth", Severity.LOW, f"spf={spf}", "SPF could not be evaluated cleanly"))

    if dkim == "fail":
        findings.append(Indicator("email_auth", Severity.MEDIUM, "dkim=fail", "A DKIM signature failed verification"))
    elif dkim == "none" and not email.dkim_signatures:
        findings.append(Indicator("email_auth", Severity.LOW, "dkim=none", "Message carries no DKIM signature"))

    if spf == "fail" and dkim in ("fail", "none") and dmarc not in ("pass", "fail"):
        findings.append(
            Indicator("email_auth", Severity.HIGH, "spf+dkim", "SPF and DKIM both failed and DMARC did not pass")
        )

    if verdict.spf_domain and email.from_domain and not aligns(email.from_domain, verdict.spf_domain):
        findings.append(
            Indicator(
                "identity",
                Severity.LOW,
                f"envelope={verdict.spf_domain}",
                f"Envelope sender domain {verdict.spf_domain} differs from the From domain {email.from_domain}, common with mailing providers but worth checking",
            )
        )

    if email.reply_to and "@" in email.reply_to:
        reply_domain = email.reply_to.rsplit("@", 1)[1].lower()
        if email.from_domain and not aligns(email.from_domain, reply_domain):
            findings.append(
                Indicator(
                    "identity",
                    Severity.MEDIUM,
                    f"reply-to={email.reply_to}",
                    f"Replies go to {reply_domain}, not the From domain {email.from_domain}",
                )
            )

    if email.from_display and "@" in email.from_display:
        embedded = email.from_display.strip().strip("<>").lower()
        if embedded != email.from_addr.lower():
            findings.append(
                Indicator(
                    "identity",
                    Severity.MEDIUM,
                    email.from_display,
                    "Display name contains an email address that is not the actual sender",
                )
            )

    return findings
