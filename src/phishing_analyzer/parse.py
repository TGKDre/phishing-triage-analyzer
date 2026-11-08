from __future__ import annotations

import hashlib
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path

from .models import Attachment, ParsedEmail

_TEXT_TYPES = ("text/plain", "text/html")


def _decode(part: Message) -> str:
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
    except (LookupError, UnicodeDecodeError):
        pass
    payload = part.get_payload(decode=True)
    if isinstance(payload, bytes):
        return payload.decode("utf-8", errors="replace")
    return ""


def _first_address(raw: str) -> tuple[str, str]:
    pairs = getaddresses([raw]) if raw else []
    for name, addr in pairs:
        if addr:
            return name.strip(), addr.strip()
    return "", ""


def domain_of(addr: str) -> str:
    if not addr or "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].strip().lower().strip(">").strip()


def parse_eml(path: Path) -> ParsedEmail:
    path = Path(path)
    msg = BytesParser(policy=policy.default).parsebytes(path.read_bytes())

    display, addr = _first_address(str(msg.get("From") or ""))
    return_path = str(msg.get("Return-Path") or "").strip().strip("<>")
    reply_display, reply_addr = _first_address(str(msg.get("Reply-To") or ""))

    parsed = ParsedEmail(
        path=path,
        subject=str(msg.get("Subject") or "").strip(),
        from_display=display,
        from_addr=addr,
        from_domain=domain_of(addr),
        return_path=return_path,
        reply_to=reply_addr or reply_display,
        date=str(msg.get("Date") or "").strip(),
        message_id=str(msg.get("Message-ID") or "").strip(),
        auth_results=[str(v) for v in msg.get_all("Authentication-Results", [])],
        received_spf=[str(v) for v in msg.get_all("Received-SPF", [])],
        dkim_signatures=[str(v) for v in msg.get_all("DKIM-Signature", [])],
        received=[str(v) for v in msg.get_all("Received", [])],
    )

    text_chunks: list[str] = []
    html_chunks: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        filename = part.get_filename()
        disposition = part.get_content_disposition()

        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            parsed.attachments.append(
                Attachment(
                    filename=filename or "(unnamed attachment)",
                    content_type=ctype,
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
            continue

        if ctype == "text/plain":
            text_chunks.append(_decode(part))
        elif ctype == "text/html":
            html_chunks.append(_decode(part))

    parsed.text_body = "\n".join(c for c in text_chunks if c)
    parsed.html_body = "\n".join(c for c in html_chunks if c)
    return parsed
