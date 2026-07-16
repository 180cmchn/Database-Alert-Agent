from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Protocol

from tools.qq_mail_relay.settings import RelaySettings, SMTPSecurity

logger = logging.getLogger(__name__)


class MailDeliveryError(RuntimeError):
    pass


class Mailer(Protocol):
    async def send(self, message: EmailMessage) -> None: ...


class QQSMTPMailer:
    def __init__(self, settings: RelaySettings) -> None:
        self._settings = settings
        self._semaphore = asyncio.Semaphore(1)

    async def send(self, message: EmailMessage) -> None:
        if self._settings.dry_run:
            logger.info(
                "qq_mail_relay dry_run delivery subject=%s recipient=%s",
                message.get("Subject", ""),
                self._settings.mail_to,
            )
            return
        async with self._semaphore:
            try:
                await asyncio.to_thread(self._send_sync, message)
            except (OSError, smtplib.SMTPException) as exc:
                logger.warning("qq_mail_relay SMTP delivery failed type=%s", type(exc).__name__)
                raise MailDeliveryError("SMTP delivery failed") from exc

    def _send_sync(self, message: EmailMessage) -> None:
        settings = self._settings
        context = ssl.create_default_context()
        auth_code = settings.smtp_auth_code.get_secret_value()
        recipients = [settings.mail_to]

        if settings.smtp_security == SMTPSecurity.SSL:
            with smtplib.SMTP_SSL(
                settings.smtp_host,
                settings.smtp_port,
                timeout=settings.smtp_timeout_seconds,
                context=context,
            ) as client:
                client.login(settings.smtp_username, auth_code)
                client.send_message(
                    message,
                    from_addr=settings.sender_address,
                    to_addrs=recipients,
                )
            return

        if settings.smtp_security == SMTPSecurity.STARTTLS:
            with smtplib.SMTP(
                settings.smtp_host,
                settings.smtp_port,
                timeout=settings.smtp_timeout_seconds,
            ) as client:
                client.ehlo()
                client.starttls(context=context)
                client.ehlo()
                client.login(settings.smtp_username, auth_code)
                client.send_message(
                    message,
                    from_addr=settings.sender_address,
                    to_addrs=recipients,
                )
            return

        raise MailDeliveryError("Unsupported SMTP security mode")
