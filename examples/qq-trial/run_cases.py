from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
TERMINAL_STATUSES = {"COMPLETED", "REVIEW_REQUIRED", "FAILED"}


def request_json(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    *,
    timeout_seconds: int = 60,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False).encode() if payload is not None else None
    request_headers = {"Content-Type": "application/json", **(headers or {})}
    request = Request(
        url,
        data=body,
        method=method,
        headers=request_headers,
    )
    try:
        with urlopen(  # noqa: S310 - URL is operator supplied
            request, timeout=timeout_seconds
        ) as response:
            parsed = json.loads(response.read().decode())
    except HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {exc.code} from {url}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"Cannot reach {url}: {exc.reason}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"Expected a JSON object from {url}")
    return parsed


def load_manifest() -> dict[str, Any]:
    return json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))


def verify_webhook_runtime(base_url: str) -> None:
    token = os.getenv("ADMIN_API_TOKEN", "").strip()
    if not token:
        if not sys.stdin.isatty():
            raise RuntimeError(
                "--require-webhook needs ADMIN_API_TOKEN in the environment "
                "when no interactive terminal is available"
            )
        token = getpass.getpass("ADMIN_API_TOKEN（输入不会显示）: ").strip()
    if not token:
        raise RuntimeError("ADMIN_API_TOKEN is required to verify runtime notifier settings")

    settings = request_json(
        "GET",
        f"{base_url}/api/v1/admin/settings",
        timeout_seconds=15,
        headers={"Authorization": f"Bearer {token}"},
    )
    if settings.get("notifier_mode") != "webhook":
        raise RuntimeError("Runtime NOTIFIER_MODE is not webhook; QQ will not receive messages")
    if not settings.get("management_webhook_url"):
        raise RuntimeError("Runtime MANAGEMENT_WEBHOOK_URL is empty")
    if "CRITICAL" not in settings.get("escalation_severities", []):
        raise RuntimeError("Runtime ESCALATION_SEVERITIES does not include CRITICAL")
    print("已确认运行时使用 Webhook 通知，且 CRITICAL 位于升级等级中。")


def wait_for_result(base_url: str, detail_url: str, timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    url = f"{base_url}{detail_url}"
    while time.monotonic() < deadline:
        detail = request_json("GET", url, timeout_seconds=15)
        if detail.get("status") in TERMINAL_STATUSES:
            return detail
        time.sleep(1)
    raise RuntimeError(f"Timed out after {timeout_seconds}s waiting for {detail_url}")


def validate_case(case: dict[str, Any], detail: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if detail.get("status") == "FAILED":
        errors.append(f"分析失败：{detail.get('error') or '未提供错误信息'}")

    expected_matches = case["expected_manual_matches"]
    expected_section = case["expected_section"]
    manual_matches = detail.get("manual_matches", [])
    actual_matches = [item["runbook_id"] for item in manual_matches]
    if actual_matches != expected_matches:
        errors.append(f"手册匹配预期 {expected_matches}，实际 {actual_matches}")
    actual_sections = {item["section"] for item in manual_matches}
    if expected_matches and actual_sections != {expected_section}:
        errors.append(f"手册章节预期 {expected_section}，实际 {sorted(actual_sections)}")

    recommendation = detail.get("recommendation")
    if expected_matches:
        if not recommendation or recommendation.get("manual_matched") is not True:
            errors.append("命中手册的告警缺少 manual_matched=true 的建议")
        else:
            cited = {
                (item["runbook_id"], item["section"])
                for item in recommendation.get("runbook_references", [])
            }
            valid_references = {
                (runbook_id, expected_section) for runbook_id in expected_matches
            }
            if not cited or not cited.issubset(valid_references):
                errors.append(f"建议中的手册引用不符合预期：{sorted(cited)}")
            for index, step in enumerate(recommendation.get("steps", []), start=1):
                source_ref = step.get("source_ref")
                reference = (
                    (source_ref.get("runbook_id"), source_ref.get("section"))
                    if source_ref
                    else None
                )
                if reference not in valid_references:
                    errors.append(f"建议步骤 #{index} 的手册引用不符合预期：{reference}")
    elif recommendation:
        if recommendation.get("manual_matched") is not False:
            errors.append("未命中告警应返回 manual_matched=false")
        if float(recommendation.get("confidence", 1)) > 0.45:
            errors.append("未命中告警的建议置信度应不超过 0.45")

    rule_validations = [
        item for item in detail.get("validations", []) if item.get("kind") == "RULE"
    ]
    if not rule_validations:
        errors.append("缺少规则验收记录")
    elif any(item.get("passed") is not True for item in rule_validations):
        issues = [issue for item in rule_validations for issue in item.get("issues", [])]
        errors.append(f"规则验收未通过：{issues}")

    notification_records = detail.get("notifications", [])
    phases = [item["phase"] for item in notification_records]
    if case["expects_management_notification"]:
        if "INITIAL_ALERT" not in phases:
            errors.append("CRITICAL 告警缺少 INITIAL_ALERT 通知记录")
        if not ({"ADVICE_READY", "ANALYSIS_FAILED"} & set(phases)):
            errors.append("CRITICAL 告警缺少最终阶段通知记录")
        failed_phases = [
            item["phase"] for item in notification_records if item["status"] != "SENT"
        ]
        if failed_phases:
            errors.append(f"管理通知发送失败：{failed_phases}")
    elif phases:
        errors.append(f"非 CRITICAL 告警不应通知管理人员，实际阶段为 {phases}")
    return errors


def run_case(
    case: dict[str, Any], base_url: str, timeout_seconds: int, verify_idempotency: bool
) -> bool:
    payload_path = ROOT / case["file"]
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    payload["external_id"] = f"{payload['external_id']}-{time.time_ns()}"

    accepted = request_json(
        "POST", f"{base_url}/api/v1/alerts/canonical/analyze", payload
    )
    print(f"\n[{case['name']}] {case['purpose']}")
    print(f"  alert_id: {accepted['alert_id']}")
    print(f"  deduplicated: {accepted['deduplicated']}")

    detail = wait_for_result(base_url, accepted["detail_url"], timeout_seconds)
    matches = [
        f"{item['runbook_id']} (score={item['score']})"
        for item in detail.get("manual_matches", [])
    ]
    notifications = [
        f"{item['phase']}:{item['status']}" for item in detail.get("notifications", [])
    ]
    print(f"  status: {detail['status']}")
    print(f"  manual_matches: {matches or '[]'}")
    print(f"  notifications: {notifications or '[]'}")

    errors = validate_case(case, detail)
    if accepted.get("deduplicated") is not False:
        errors.append("首次发送使用了唯一 external_id，但接口将其标记为重复事件")

    if verify_idempotency and not errors:
        duplicate = request_json(
            "POST", f"{base_url}/api/v1/alerts/canonical/analyze", payload
        )
        duplicate_detail = request_json("GET", f"{base_url}{duplicate['detail_url']}")
        original_phases = [item["phase"] for item in detail.get("notifications", [])]
        duplicate_phases = [
            item["phase"] for item in duplicate_detail.get("notifications", [])
        ]
        if duplicate.get("deduplicated") is not True:
            errors.append("第二次发送相同 external_id 未返回 deduplicated=true")
        if duplicate.get("alert_id") != accepted.get("alert_id"):
            errors.append("重复事件没有复用首次 alert_id")
        if duplicate_phases != original_phases:
            errors.append(
                f"重复事件改变了通知阶段：首次 {original_phases}，重复后 {duplicate_phases}"
            )
        if not errors:
            print("  idempotency: PASS（复用 alert_id，未增加通知）")

    if errors:
        for error in errors:
            print(f"  FAIL: {error}")
        return False
    print("  PASS")
    return True


def parse_args(manifest: dict[str, Any]) -> argparse.Namespace:
    names = [case["name"] for case in manifest["cases"]]
    parser = argparse.ArgumentParser(description="发送并验证 QQ 试运行告警样例")
    parser.add_argument("--case", choices=["all", *names], default=names[0])
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument(
        "--verify-idempotency",
        action="store_true",
        help="在同一次运行中重复发送相同 external_id，并验证复用结果且不增加通知",
    )
    parser.add_argument(
        "--require-webhook",
        action="store_true",
        help="通过管理接口确认运行时使用 Webhook；令牌从环境读取或安全提示输入",
    )
    return parser.parse_args()


def main() -> int:
    manifest = load_manifest()
    args = parse_args(manifest)
    base_url = args.base_url.rstrip("/")
    selected = [
        case
        for case in manifest["cases"]
        if args.case == "all" or case["name"] == args.case
    ]
    try:
        if args.timeout <= 0:
            raise ValueError("--timeout must be greater than zero")
        if args.require_webhook:
            verify_webhook_runtime(base_url)
        passed = [
            run_case(case, base_url, args.timeout, args.verify_idempotency)
            for case in selected
        ]
    except (KeyError, OSError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if all(passed) and args.require_webhook:
        print("\nWebhook 已接受通知；请在 QQ 客户端或中转服务回执中确认最终到达。")
    return 0 if all(passed) else 1


if __name__ == "__main__":
    raise SystemExit(main())
