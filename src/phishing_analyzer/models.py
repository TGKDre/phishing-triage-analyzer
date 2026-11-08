from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


class Severity:
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class ParsedEmail:
    path: Path
    subject: str
    from_display: str
    from_addr: str
    from_domain: str
    return_path: str
    reply_to: str
    date: str
    message_id: str
    auth_results: list[str] = field(default_factory=list)
    received_spf: list[str] = field(default_factory=list)
    dkim_signatures: list[str] = field(default_factory=list)
    received: list[str] = field(default_factory=list)
    text_body: str = ""
    html_body: str = ""
    attachments: list[Attachment] = field(default_factory=list)


@dataclass
class AuthVerdict:
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    spf_domain: str = ""
    dkim_domain: str = ""
    dmarc_domain: str = ""
    dmarc_policy: str = ""
    source: str = ""


@dataclass
class Indicator:
    category: str
    severity: str
    value: str
    detail: str


@dataclass
class Analysis:
    path: Path
    subject: str
    from_display: str
    from_addr: str
    from_domain: str
    return_path: str
    reply_to: str
    date: str
    auth: AuthVerdict
    indicators: list[Indicator] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    score: int = 0
    verdict: str = "clean"
    reasons: list[str] = field(default_factory=list)
