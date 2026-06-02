"""数据库公网暴露巡检规则。"""

from __future__ import annotations

import re

from .helpers import evidence_from_pairs, finding
from .models import CheckContext, CheckFinding


def run(context: CheckContext) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    findings.extend(check_rds_public_endpoint(context))
    findings.extend(check_redis_public_endpoint(context))
    return findings


def check_rds_public_endpoint(context: CheckContext) -> list[CheckFinding]:
    check_id = "rds_public_endpoint"
    if not context.config.is_enabled(check_id):
        return []

    whitelist_by_instance = rds_whitelists_by_instance(context.details.rds_ip_arrays)
    findings = []
    for row in context.details.rds_net_infos:
        if not is_public_endpoint(row):
            continue
        instance_id = row.get("instance_id", "")
        # 白名单已经收敛时，公网地址本身不等于暴露面，避免把受控运维入口误判成风险。
        if rds_whitelist_confirms_restricted_access(whitelist_by_instance.get(instance_id, [])):
            continue
        findings.append(
            finding(
                row,
                service="rds（云数据库RDS）",
                resource_type="RDS连接地址",
                severity="medium",
                check_id=check_id,
                check_name="RDS 存在公网连接地址",
                category="高风险暴露",
                message="RDS 实例存在公网连接地址。",
                recommendation="确认公网访问是否为业务必要；非必要场景建议关闭公网地址并通过 VPC 内网访问。",
                evidence=evidence_from_pairs(
                    实例=row.get("instance_id"),
                    网络类型=row.get("net_type"),
                    连接地址=row.get("connection_string"),
                    端口=row.get("port"),
                    白名单=rds_whitelist_summary(whitelist_by_instance.get(instance_id, [])),
                ),
            )
        )
    return findings


def check_redis_public_endpoint(context: CheckContext) -> list[CheckFinding]:
    check_id = "redis_public_endpoint"
    if not context.config.is_enabled(check_id):
        return []

    findings = []
    for row in context.details.redis_net_infos:
        if not is_public_endpoint(row):
            continue
        findings.append(
            finding(
                row,
                service="redis（Redis/Tair）",
                resource_type="Redis连接地址",
                severity="medium",
                check_id=check_id,
                check_name="Redis 存在公网连接地址",
                category="高风险暴露",
                message="Redis/Tair 实例存在公网连接地址。",
                recommendation="确认公网访问是否为业务必要；非必要场景建议关闭公网地址并通过 VPC 内网访问。",
                evidence=evidence_from_pairs(
                    实例=row.get("instance_id"),
                    网络类型=row.get("net_type"),
                    连接地址=row.get("connection_string"),
                    端口=row.get("port"),
                ),
            )
        )
    return findings


def is_public_endpoint(row: dict[str, str]) -> bool:
    text = " ".join(
        str(row.get(key, "")).lower()
        for key in ("net_type", "ip_type", "connection_string", "address_type")
    )
    return any(marker in text for marker in ("public", "internet", "公网", "外网"))


def rds_whitelists_by_instance(rows: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    whitelists: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        instance_id = row.get("instance_id", "")
        if not instance_id:
            continue
        whitelists.setdefault(instance_id, []).append(row)
    return whitelists


def rds_whitelist_confirms_restricted_access(rows: list[dict[str, str]]) -> bool:
    if not rows:
        return False
    if any(row.get("status") == "query_failed" for row in rows):
        return False

    seen_ip_list = False
    for row in rows:
        security_ip_list = str(row.get("security_ip_list", "")).strip()
        if not security_ip_list:
            return False
        seen_ip_list = True
        if rds_whitelist_has_public_opening(security_ip_list):
            return False
    return seen_ip_list


def rds_whitelist_has_public_opening(security_ip_list: str) -> bool:
    tokens = {
        token.strip()
        for token in re.split(r"[,\s;]+", str(security_ip_list or "").strip())
        if token.strip()
    }
    return any(token in {"0.0.0.0/0", "::/0"} for token in tokens)


def rds_whitelist_summary(rows: list[dict[str, str]]) -> str:
    parts = []
    for row in rows:
        whitelist_name = str(row.get("whitelist_name", "")).strip() or "未命名"
        whitelist_attribute = str(row.get("whitelist_attribute", "")).strip()
        security_ip_list = str(row.get("security_ip_list", "")).strip()
        if not security_ip_list and row.get("status") != "query_failed":
            continue
        label = whitelist_name
        if whitelist_attribute:
            label = f"{label}({whitelist_attribute})"
        if security_ip_list:
            parts.append(f"{label}:{security_ip_list}")
        else:
            parts.append(f"{label}:query_failed")
    return "; ".join(parts)
