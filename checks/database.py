"""数据库公网暴露巡检规则。"""

from __future__ import annotations

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

    findings = []
    for row in context.details.rds_net_infos:
        if not is_public_endpoint(row):
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
