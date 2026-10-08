"""Extract analysable text from uploaded .txt / .eml files."""
import re
from email import policy
from email.parser import BytesParser
from html import unescape
from pathlib import Path

ALLOWED_EXTENSIONS = {".txt", ".eml"}
MAX_UPLOAD_BYTES = 1024 * 1024  # 1 MB


class InvalidEmailFile(ValueError):
    """Raised with a user-presentable message."""


def _decode(raw: bytes) -> str:
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise InvalidEmailFile("Invalid file format.")


def _html_to_text(html: str) -> str:
    html = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
    html = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>", "\n", html)
    # Keep link targets visible so the URL analyser can see them.
    html = re.sub(r'(?is)<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', r"\2 (\1)", html)
    text = unescape(re.sub(r"(?s)<[^>]+>", " ", html))
    return re.sub(r"[ \t]+", " ", re.sub(r"\n\s*\n+", "\n\n", text)).strip()


def extract_email_text(filename: str, raw: bytes) -> dict:
    extension = Path(filename or "").suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise InvalidEmailFile("Invalid file format. Please upload a .txt or .eml file.")
    if not raw:
        raise InvalidEmailFile("The uploaded file is empty.")
    if len(raw) > MAX_UPLOAD_BYTES:
        raise InvalidEmailFile("File is too large (limit 1 MB).")
    if b"\x00" in raw[:2048]:
        raise InvalidEmailFile("Invalid file format.")

    if extension == ".txt":
        text = _decode(raw).strip()
        subject = sender = None
    else:
        try:
            message = BytesParser(policy=policy.default).parsebytes(raw)
            part = message.get_body(preferencelist=("plain", "html"))
            body = part.get_content() if part is not None else ""
            if part is not None and part.get_content_type() == "text/html":
                body = _html_to_text(body)
            subject, sender = message["subject"], message["from"]
        except Exception as exc:  # malformed MIME
            raise InvalidEmailFile("Could not read this .eml file.") from exc
        header = f"Subject: {subject}\n\n" if subject else ""
        text = (header + (body or "")).strip()

    if not text:
        raise InvalidEmailFile("No email content found in the file.")
    return {"text": text, "subject": str(subject) if subject else None,
            "sender": str(sender) if sender else None, "filename": filename}
