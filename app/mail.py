"""Outbound mail.

With no SMTP host configured the message is written to ``$SL_DATA_DIR/outbox``
as an .eml file, so verification links and alert mail are inspectable in
development without pretending they were delivered.
"""
from __future__ import annotations

import smtplib
from email.message import EmailMessage
from pathlib import Path


def send(data_dir: Path, from_addr: str, to_addr: str, subject: str,
         text: str, smtp_host: str | None = None) -> str:
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(text)
    if smtp_host:
        with smtplib.SMTP(smtp_host, timeout=15) as smtp:
            smtp.send_message(msg)
        return "sent"
    outbox = data_dir / "outbox"
    outbox.mkdir(parents=True, exist_ok=True)
    name = f"{abs(hash((to_addr, subject, text))) & 0xFFFFFFFF:08x}.eml"
    (outbox / name).write_bytes(bytes(msg))
    return "queued"
