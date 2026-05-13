"""巡检规则共用工具。"""

from __future__ import annotations

import json
from typing import Any

from .models import CheckFinding


def first_value(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def resource_key(row: dict[str, str]) -> tuple[str, str, str]:
    return (
        row.get("subscription", ""),
        row.get("region_id", ""),
        row.get("resource_id", ""),
    )


def rows_by_type(
    rows: list[dict[str, str]],
    resource_types: set[str],
) -> list[dict[str, str]]:
    return [row for row in rows if row.get("resource_type") in resource_types]


def rows_by_service(
    rows: list[dict[str, str]],
    services: set[str],
) -> list[dict[str, str]]:
    return [row for row in rows if row.get("service_code") in services]


def evidence_from_pairs(**pairs: Any) -> str:
    parts = []
    for key, value in pairs.items():
        if value in (None, "", [], {}):
            continue
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        parts.append(f"{key}={value}")
    return "; ".join(parts)


def finding(
    row: dict[str, str],
    *,
    service: str,
    resource_type: str,
    severity: str,
    check_id: str,
    check_name: str,
    category: str,
    message: str,
    recommendation: str,
    evidence: str,
) -> CheckFinding:
    return CheckFinding(
        subscription=row.get("subscription", ""),
        account_id=row.get("account_id", ""),
        region_id=row.get("region_id", ""),
        service=service,
        resource_type=resource_type,
        resource_id=first_value(
            row,
            "resource_id",
            "instance_id",
            "disk_id",
            "security_group_id",
            "allocation_id",
            "load_balancer_id",
            "server_group_id",
            "user_name",
            "bucket_name",
        ),
        resource_name=first_value(
            row,
            "resource_name",
            "instance_name",
            "disk_name",
            "security_group_name",
            "name",
            "load_balancer_name",
            "server_group_name",
            "user_name",
            "bucket_name",
        ),
        severity=severity,
        check_id=check_id,
        check_name=check_name,
        category=category,
        finding=message,
        recommendation=recommendation,
        evidence=evidence,
        tags=first_value(row, "tags"),
        resource_group_id=first_value(row, "resource_group_id"),
    )


def split_semicolon(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(";") if item.strip()]


def masked_identifier(value: str) -> str:
    text = str(value or "")
    if len(text) <= 8:
        return "****"
    return f"{text[:4]}****{text[-4:]}"
