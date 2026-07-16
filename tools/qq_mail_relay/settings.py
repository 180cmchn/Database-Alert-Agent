from __future__ import annotations

from email.utils import parseaddr
from enum import StrEnum
from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class SMTPSecurity(StrEnum):
    SSL = "ssl"
    STARTTLS = "starttls"


def _is_plain_email_address(value: str) -> bool:
    if not value or "\r" in value or "\n" in value:
        return False
    display_name, parsed = parseaddr(value)
    return not display_name and parsed == value and value.count("@") == 1


class RelaySettings(BaseSettings):
    """Configuration isolated behind the QQ_MAIL_RELAY_ prefix."""

    model_config = SettingsConfigDict(
        env_prefix="QQ_MAIL_RELAY_",
        case_sensitive=False,
        extra="ignore",
        hide_input_in_errors=True,
    )

    bearer_token: SecretStr = SecretStr("")
    dry_run: bool = True

    smtp_host: str = "smtp.qq.com"
    smtp_port: int = Field(default=465, ge=1, le=65535)
    smtp_security: SMTPSecurity = SMTPSecurity.SSL
    smtp_username: str = ""
    smtp_auth_code: SecretStr = SecretStr("")
    smtp_timeout_seconds: float = Field(default=10, gt=0, le=60)

    mail_from: str = ""
    mail_to: str = ""
    subject_prefix: str = "[Database Alert Agent]"
    max_body_chars: int = Field(default=32_000, ge=4_096, le=100_000)
    database_path: Path = Path("./data/qq-mail-relay.db")

    @field_validator("smtp_host", "smtp_username", "mail_from", "mail_to", mode="before")
    @classmethod
    def strip_text(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @field_validator("subject_prefix")
    @classmethod
    def validate_subject_prefix(cls, value: str) -> str:
        value = " ".join(value.replace("\r", " ").replace("\n", " ").split())
        if len(value) > 80:
            raise ValueError("subject_prefix must be at most 80 characters")
        return value

    @property
    def sender_address(self) -> str:
        return self.mail_from or self.smtp_username

    def readiness_issues(self) -> list[str]:
        issues: list[str] = []
        if len(self.bearer_token.get_secret_value()) < 32:
            issues.append("QQ_MAIL_RELAY_BEARER_TOKEN must contain at least 32 characters")

        if not _is_plain_email_address(self.sender_address):
            issues.append("QQ_MAIL_RELAY_MAIL_FROM must be a plain email address")
        if not _is_plain_email_address(self.mail_to):
            issues.append("QQ_MAIL_RELAY_MAIL_TO must be a plain email address")

        if not self.dry_run:
            if not self.smtp_host:
                issues.append("QQ_MAIL_RELAY_SMTP_HOST is required")
            if not _is_plain_email_address(self.smtp_username):
                issues.append("QQ_MAIL_RELAY_SMTP_USERNAME must be a plain email address")
            if not self.smtp_auth_code.get_secret_value():
                issues.append("QQ_MAIL_RELAY_SMTP_AUTH_CODE is required")
            if (
                _is_plain_email_address(self.smtp_username)
                and _is_plain_email_address(self.sender_address)
                and self.smtp_username.casefold() != self.sender_address.casefold()
            ):
                issues.append("QQ_MAIL_RELAY_MAIL_FROM must match QQ_MAIL_RELAY_SMTP_USERNAME")
        return issues
