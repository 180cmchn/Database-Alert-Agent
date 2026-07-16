from __future__ import annotations

import re
from email.message import EmailMessage
from typing import Any

from app.application.sanitization import sanitize
from app.domain.models import NotificationEvent, NotificationPhase
from tools.qq_mail_relay.settings import RelaySettings

_WHITESPACE = re.compile(r"\s+")
_PHASE_LABELS = {
    NotificationPhase.INITIAL_ALERT: "首次升级",
    NotificationPhase.ADVICE_READY: "分析完成",
    NotificationPhase.ANALYSIS_FAILED: "分析失败",
}


def _single_line(value: Any, limit: int = 500) -> str:
    text = str(sanitize(value) if value is not None else "-")
    text = _WHITESPACE.sub(" ", text.replace("\r", " ").replace("\n", " ")).strip()
    if not text:
        return "-"
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


def _multiline(value: Any, limit: int = 2_000) -> str:
    text = str(sanitize(value) if value is not None else "-").strip()
    if not text:
        return "-"
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


def _database_target(event: NotificationEvent) -> str:
    target = event.alert.database
    if target is None:
        return "-"
    fields = [target.engine, target.instance, target.database, target.host]
    values = [_single_line(item, 200) for item in fields if item]
    return " / ".join(values) if values else "-"


def format_notification_text(event: NotificationEvent, max_body_chars: int = 32_000) -> str:
    safe_event = NotificationEvent.model_validate(sanitize(event.model_dump(mode="json")))
    alert = safe_event.alert
    phase_label = _PHASE_LABELS[safe_event.phase]
    lines = [
        "数据库告警 AI Agent 通知",
        "",
        f"通知阶段：{phase_label} ({safe_event.phase.value})",
        f"通知说明：{_multiline(safe_event.message)}",
        f"告警 ID：{alert.id}",
        f"外部 ID：{_single_line(alert.external_id)}",
        f"来源：{_single_line(alert.source)}",
        f"等级：{alert.severity.value}（原始等级：{_single_line(alert.raw_severity)}）",
        f"发生时间：{alert.occurred_at.isoformat()}",
        f"环境：{_single_line(alert.environment)}",
        f"服务：{_single_line(alert.service_name)}",
        f"标题：{_multiline(alert.title)}",
        f"原因：{_multiline(alert.reason)}",
        f"描述：{_multiline(alert.description, 4_000)}",
        f"数据库：{_database_target(safe_event)}",
    ]

    recommendation = safe_event.recommendation
    if recommendation is not None:
        lines.extend(
            [
                "",
                "AI 处理建议",
                f"摘要：{_multiline(recommendation.summary, 4_000)}",
                f"置信度：{recommendation.confidence:.2f}",
                f"需要人工介入：{'是' if recommendation.requires_human else '否'}",
                f"命中手册：{'是' if recommendation.manual_matched else '否'}",
            ]
        )
        if recommendation.likely_causes:
            lines.append("可能原因：")
            lines.extend(
                f"- {_multiline(cause, 1_000)}" for cause in recommendation.likely_causes[:3]
            )
        if recommendation.steps:
            lines.append("处理步骤：")
            for step in recommendation.steps[:5]:
                lines.append(f"{step.order}. {_multiline(step.action, 2_000)}")
                if step.expected_result:
                    lines.append(f"   预期：{_multiline(step.expected_result, 1_000)}")
                if step.caution:
                    lines.append(f"   注意：{_multiline(step.caution, 1_000)}")
                if step.source_ref:
                    lines.append(
                        "   手册："
                        f"{_single_line(step.source_ref.runbook_id, 200)}"
                        f" / {_single_line(step.source_ref.section, 200)}"
                    )
        if recommendation.risks:
            lines.append("风险提示：")
            lines.extend(f"- {_multiline(risk, 1_000)}" for risk in recommendation.risks[:3])
        if recommendation.runbook_references:
            lines.append("手册引用：")
            lines.extend(
                f"- {_single_line(reference.runbook_id, 200)}"
                f" / {_single_line(reference.section, 200)}"
                for reference in recommendation.runbook_references[:5]
            )

    body = "\n".join(lines)
    if len(body) > max_body_chars:
        marker = "\n\n[正文过长，已由 QQ 邮件中转服务截断]"
        body = f"{body[: max_body_chars - len(marker)]}{marker}"
    return body


def build_email(
    event: NotificationEvent,
    settings: RelaySettings,
    delivery_id: str,
) -> EmailMessage:
    safe_title = _single_line(event.alert.title, 160)
    phase_label = _PHASE_LABELS[event.phase]
    prefix = f"{settings.subject_prefix} " if settings.subject_prefix else ""
    subject = _single_line(
        f"{prefix}[DB告警][{event.alert.severity.value}][{phase_label}] {safe_title}",
        240,
    )

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.sender_address
    message["To"] = settings.mail_to
    message["Message-ID"] = f"<{delivery_id}@database-alert-agent.local>"
    message["Auto-Submitted"] = "auto-generated"
    message["X-Alert-Id"] = str(event.alert.id)
    message["X-Notification-Phase"] = event.phase.value
    message.set_content(
        format_notification_text(event, settings.max_body_chars),
        subtype="plain",
        charset="utf-8",
    )
    return message
