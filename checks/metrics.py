"""云监控指标类疑似闲置巡检规则。"""

from __future__ import annotations

from collections import defaultdict

from .helpers import evidence_from_pairs, finding
from .models import CheckContext, CheckFinding


CHECK_RULES = {
    "metric_idle_ecs": {
        "service": "ecs（云服务器）",
        "resource_type": "云服务器",
        "name": "ECS 低使用率",
        "roles": {"ecs_cpu", "ecs_network_out"},
        "thresholds": {
            "ecs_cpu": "ecs_cpu_avg_percent",
            "ecs_network_out": "ecs_network_out_avg_bps",
        },
    },
    "metric_idle_eip": {
        "service": "eip（弹性公网IP）",
        "resource_type": "弹性公网IP",
        "name": "EIP 低流量",
        "roles": {"eip_traffic"},
        "thresholds": {"eip_traffic": "eip_traffic_avg_bps"},
    },
    "metric_idle_slb": {
        "service": "slb（传统型负载均衡）",
        "resource_type": "负载均衡",
        "name": "SLB 低 QPS",
        "roles": {"slb_qps"},
        "thresholds": {"slb_qps": "slb_qps_avg"},
    },
    "metric_idle_rds": {
        "service": "rds（云数据库RDS）",
        "resource_type": "RDS实例",
        "name": "RDS 低连接数",
        "roles": {"rds_connections"},
        "thresholds": {"rds_connections": "rds_connection_avg"},
    },
    "metric_idle_redis": {
        "service": "redis（Redis/Tair）",
        "resource_type": "Redis/Tair实例",
        "name": "Redis 低 QPS",
        "roles": {"redis_qps"},
        "thresholds": {"redis_qps": "redis_qps_avg"},
    },
}


def run(context: CheckContext) -> list[CheckFinding]:
    if not context.config.metric_checks_enabled:
        return []

    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in context.details.metric_summaries:
        if row.get("query_failed") == "true" or row.get("datapoints") in {"", "0"}:
            continue
        grouped[(row.get("check_id", ""), row.get("resource_id", ""))].append(row)

    findings: list[CheckFinding] = []
    for (check_id, resource_id), rows in grouped.items():
        rule = CHECK_RULES.get(check_id)
        if not rule or not context.config.is_enabled(check_id) or not resource_id:
            continue
        roles = {row.get("metric_role", "") for row in rows}
        if not set(rule["roles"]).issubset(roles):
            continue
        if not all_metric_values_below_threshold(context, rows, rule["thresholds"]):
            continue
        base = rows[0]
        findings.append(
            finding(
                base,
                service=str(rule["service"]),
                resource_type=str(rule["resource_type"]),
                severity="low",
                check_id=check_id,
                check_name=str(rule["name"]),
                category="疑似闲置",
                message="近 7/14/30 天云监控指标持续低于阈值，判定为疑似闲置。",
                recommendation="结合业务窗口、监控告警和负责人确认；确认无使用计划后再进入降配或释放流程。",
                evidence=evidence_from_pairs(
                    指标=";".join(metric_evidence(row) for row in rows),
                ),
            )
        )
    return findings


def all_metric_values_below_threshold(
    context: CheckContext,
    rows: list[dict[str, str]],
    threshold_keys: dict[str, str],
) -> bool:
    for row in rows:
        role = row.get("metric_role", "")
        threshold_key = threshold_keys.get(role)
        if not threshold_key:
            continue
        threshold = context.config.metric_thresholds.get(threshold_key, 0.0)
        try:
            avg = float(row.get("average", "0") or 0)
            maximum = float(row.get("maximum", "0") or 0)
        except ValueError:
            return False
        if avg > threshold or maximum > threshold * 3:
            return False
    return True


def metric_evidence(row: dict[str, str]) -> str:
    return (
        f"{row.get('metric_role')}[{row.get('window_days')}天]"
        f" avg={row.get('average')} max={row.get('maximum')}"
        f" points={row.get('datapoints')}"
    )
