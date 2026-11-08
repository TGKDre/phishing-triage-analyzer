from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .models import Indicator, ParsedEmail, Severity

_URL = re.compile(r"\bhttps?://[^\s<>\"'\)\]]+", re.IGNORECASE)
_HREF = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_BARE_HOST = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>\"']*)?", re.IGNORECASE)

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
}

BRANDS = [
    "microsoft",
    "office365",
    "outlook",
    "paypal",
    "apple",
    "icloud",
    "amazon",
    "google",
    "docusign",
    "adobe",
    "dropbox",
    "netflix",
    "chase",
    "wellsfargo",
    "bankofamerica",
]

CREDENTIAL_WORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "password",
    "confirm",
    "unlock",
    "billing",
    "invoice",
    "mfa",
    "auth",
}

DANGEROUS_EXT = {
    "exe",
    "scr",
    "pif",
    "bat",
    "cmd",
    "js",
    "jse",
    "vbs",
    "vbe",
    "hta",
    "wsf",
    "lnk",
    "iso",
    "img",
    "reg",
}

ATTACHMENT_EXEC_EXT = DANGEROUS_EXT | {"com"}

MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm"}
ARCHIVE_EXT = {"zip", "rar", "7z", "tar", "gz", "cab", "ace", "jar"}

TWO_LEVEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.nz",
    "co.za",
    "com.br",
    "com.mx",
    "co.in",
    "com.sg",
    "co.jp",
    "com.cn",
}


def registrable(domain: str) -> str:
    labels = [part for part in domain.lower().strip(".").split(".") if part]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        previous = current
    return previous[-1]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_urls(text: str, html: str) -> list[str]:
    found: list[str] = []
    for chunk in (text or "", html or ""):
        found.extend(_URL.findall(chunk))
        found.extend(_HREF.findall(chunk))
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in found:
        value = raw.strip().rstrip(".,);]'\"")
        if not value:
            continue
        if not re.match(r"^[a-z]+://", value, re.IGNORECASE):
            value = "http://" + value
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(value)
    return cleaned


def defang(url: str) -> str:
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def _brand_hit(host: str) -> str:
    host = host.lower()
    for label in host.split("."):
        for token in label.split("-"):
            if not token:
                continue
            for brand in BRANDS:
                if token == brand or (len(token) >= 6 and levenshtein(token, brand) <= 1):
                    if not any(host.endswith(brand + suffix) for suffix in (".com", ".net", ".org")):
                        return brand
    return ""


def _url_findings(url: str, from_domain: str) -> list[Indicator]:
    findings: list[Indicator] = []
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    path = (parts.path or "") + ("?" + parts.query if parts.query else "")

    if not host:
        return findings

    if parts.scheme == "http":
        findings.append(Indicator("url", Severity.LOW, defang(url), "Link uses plain HTTP, so traffic is not encrypted"))

    if _is_ip(host):
        findings.append(Indicator("url", Severity.HIGH, defang(url), f"Link points at a raw IP address {host} instead of a domain"))
    elif host.startswith("xn--") or ".xn--" in host:
        findings.append(Indicator("url", Severity.HIGH, defang(url), "Link uses punycode, often used to imitate a real domain"))
    elif registrable(host) in SHORTENERS:
        findings.append(Indicator("url", Severity.MEDIUM, defang(url), "Link uses a URL shortener, which hides the destination"))

    labels = host.split(".")
    extension = labels[-1] if len(labels) > 1 else ""
    if extension in DANGEROUS_EXT:
        findings.append(Indicator("url", Severity.HIGH, defang(url), f"Link host ends in .{extension}, which can serve a payload"))

    path_file = parts.path.rsplit("/", 1)[-1]
    if "." in path_file:
        file_ext = path_file.rsplit(".", 1)[-1].lower()
        if file_ext in DANGEROUS_EXT or file_ext in ARCHIVE_EXT:
            findings.append(
                Indicator("url", Severity.HIGH, defang(url), f"Link downloads a .{file_ext} file rather than showing a page")
            )

    if from_domain:
        from_reg = registrable(from_domain)
        host_reg = registrable(host)
        if host_reg and host_reg != from_reg:
            distance = levenshtein(from_reg, host_reg)
            if 0 < distance <= 2 and len(from_reg) > 6:
                findings.append(
                    Indicator(
                        "url",
                        Severity.HIGH,
                        defang(url),
                        f"Link domain {host_reg} is one or two characters from the sender domain {from_reg}",
                    )
                )
            brand = _brand_hit(host)
            if brand and not from_domain.lower().endswith(brand + ".com"):
                findings.append(
                    Indicator(
                        "url",
                        Severity.HIGH,
                        defang(url),
                        f"Link host mentions {brand} but the sender domain is {from_domain}",
                    )
                )
            path_words = {w for w in re.split(r"[^a-z0-9-]+", path.lower()) if w}
            if path_words & CREDENTIAL_WORDS:
                findings.append(
                    Indicator(
                        "url",
                        Severity.MEDIUM,
                        defang(url),
                        "Link leads to a credential or account page on a domain unrelated to the sender",
                    )
                )
    return findings


def url_findings(email: ParsedEmail) -> tuple[list[Indicator], list[str]]:
    urls = extract_urls(email.text_body, email.html_body)
    findings: list[Indicator] = []
    for url in urls:
        findings.extend(_url_findings(url, email.from_domain))
    return findings, urls


def attachment_findings(email: ParsedEmail) -> list[Indicator]:
    findings: list[Indicator] = []
    for att in email.attachments:
        name = att.filename
        lowered = name.lower()
        pieces = lowered.split(".")
        extension = pieces[-1] if len(pieces) > 1 else ""
        detail = f"{name} ({att.content_type}, {att.size} bytes, sha256 {att.sha256[:16]}...)"

        if extension in ATTACHMENT_EXEC_EXT:
            double = (
                len(pieces) > 2
                and pieces[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"}
            )
            if double:
                findings.append(
                    Indicator(
                        "attachment",
                        Severity.HIGH,
                        name,
                        f"Double extension disguises {pieces[-1]} as {pieces[-2]}: {detail}",
                    )
                )
            else:
                findings.append(Indicator("attachment", Severity.HIGH, name, f"Executable or script attachment: {detail}"))

        if extension in MACRO_EXT:
            findings.append(Indicator("attachment", Severity.HIGH, name, f"Macro-enabled Office document: {detail}"))
        if extension in ARCHIVE_EXT:
            findings.append(Indicator("attachment", Severity.MEDIUM, name, f"Archive attachment can hide a payload: {detail}"))
    return findings


def sender_domain_findings(email: ParsedEmail) -> list[Indicator]:
    findings: list[Indicator] = []
    if not email.from_domain:
        return findings
    brand = _brand_hit(email.from_domain)
    if brand:
        findings.append(
            Indicator(
                "identity",
                Severity.HIGH,
                email.from_domain,
                f"Sender domain imitates {brand} without being {brand}",
            )
        )
    return findings


def display_name_findings(email: ParsedEmail) -> list[Indicator]:
    findings: list[Indicator] = []
    if not email.from_display or not email.from_domain:
        return findings
    lowered = email.from_display.lower()
    for brand in BRANDS:
        if brand in lowered and not email.from_domain.lower().endswith(brand + ".com"):
            if brand == "office365" and "microsoft" in email.from_domain.lower():
                continue
            findings.append(
                Indicator(
                    "identity",
                    Severity.MEDIUM,
                    email.from_display,
                    f"Display name claims {brand} but the sender domain is {email.from_domain}",
                )
            )
            break
    return findings
