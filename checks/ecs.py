"""ECS 静态巡检规则。"""

from __future__ import annotations

import re

from .helpers import evidence_from_pairs, finding, split_semicolon
from .models import CheckContext, CheckFinding


def run(context: CheckContext) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    findings.extend(check_unused_disks(context))
    findings.extend(check_stopped_instances(context))
    findings.extend(check_unused_security_groups(context))
    findings.extend(check_high_risk_security_group_rules(context))
    findings.extend(check_disks_without_snapshot_policy(context))
    return findings


def check_unused_disks(context: CheckContext) -> list[CheckFinding]:
    check_id = "ecs_unused_disk"
    if not context.config.is_enabled(check_id):
        return []

    findings = []
    for disk in context.details.ecs_disks:
        status = disk.get("status", "").lower()
        if disk.get("instance_id") or status in {"in_use", "attached"}:
            continue
        findings.append(
            finding(
                disk,
                service="ecs（云服务器）",
                resource_type="云盘",
                severity="medium",
                check_id=check_id,
                check_name="未挂载云盘",
                category="闲置资源",
                message="云盘当前未挂载到 ECS 实例。",
                recommendation="确认是否仍需保留；不再使用的云盘建议按变更流程清理，清理前先确认快照和业务归属。",
                evidence=evidence_from_pairs(
                    状态=disk.get("status"),
                    容量GB=disk.get("size_gb"),
                    磁盘类型=disk.get("disk_type"),
                    创建时间=disk.get("creation_time"),
                ),
            )
        )
    return findings


def check_stopped_instances(context: CheckContext) -> list[CheckFinding]:
    check_id = "ecs_stopped_instance"
    if not context.config.is_enabled(check_id):
        return []

    findings = []
    for instance in context.details.ecs_instances:
        if instance.get("status", "").lower() != "stopped":
            continue
        findings.append(
            finding(
                instance,
                service="ecs（云服务器）",
                resource_type="云服务器",
                severity="low",
                check_id=check_id,
                check_name="已停止 ECS 实例",
                category="闲置资源",
                message="ECS 实例处于已停止状态。",
                recommendation="确认是否为保留环境；长期停止且不再使用的实例建议评估释放或降配。",
                evidence=evidence_from_pairs(
                    状态=instance.get("status"),
                    规格=instance.get("instance_type"),
                    创建时间=instance.get("creation_time"),
                    到期时间=instance.get("expired_time"),
                ),
            )
        )
    return findings


def check_unused_security_groups(context: CheckContext) -> list[CheckFinding]:
    check_id = "ecs_unused_security_group"
    if not context.config.is_enabled(check_id):
        return []

    used_security_groups = set()
    for instance in context.details.ecs_instances:
        used_security_groups.update(split_semicolon(instance.get("security_group_ids", "")))
    for eni in context.details.ecs_network_interfaces:
        used_security_groups.update(split_semicolon(eni.get("security_group_ids", "")))

    findings = []
    for group in context.details.ecs_security_groups:
        group_id = group.get("security_group_id", "")
        if not group_id or group_id in used_security_groups:
            continue
        findings.append(
            finding(
                group,
                service="ecs（云服务器）",
                resource_type="安全组",
                severity="low",
                check_id=check_id,
                check_name="安全组未绑定实例",
                category="未使用配置",
                message="安全组未绑定 ECS 实例或弹性网卡。",
                recommendation="确认是否为预留安全组；无归属且无使用计划的安全组建议按变更流程清理。",
                evidence=evidence_from_pairs(
                    VPC=group.get("vpc_id"),
                    类型=group.get("security_group_type"),
                    创建时间=group.get("creation_time"),
                ),
            )
        )
    return findings


def check_high_risk_security_group_rules(context: CheckContext) -> list[CheckFinding]:
    check_id = "ecs_high_risk_security_group_rule"
    if not context.config.is_enabled(check_id):
        return []

    high_risk_ports = context.config.high_risk_ports
    findings = []
    for rule in context.details.ecs_security_group_rules:
        if rule.get("policy", "").lower() not in {"accept", "allow", ""}:
            continue
        if rule.get("direction", "").lower() not in {"ingress", "in", ""}:
            continue
        source = rule.get("source_cidr_ip") or rule.get("ipv6_source_cidr_ip")
        if source not in {"0.0.0.0/0", "::/0"}:
            continue
        if not protocol_supports_port_range(rule.get("ip_protocol", "")):
            continue
        matched_ports = sorted(
            port for port in high_risk_ports if port_range_contains(rule.get("port_range", ""), port)
        )
        if not matched_ports:
            continue
        findings.append(
            finding(
                rule,
                service="ecs（云服务器）",
                resource_type="安全组规则",
                severity="high",
                check_id=check_id,
                check_name="安全组高危端口公网开放",
                category="高风险暴露",
                message="安全组向公网开放了高危端口。",
                recommendation="收敛来源地址到办公出口、堡垒机或业务必要网段；确认无用规则后按变更流程删除。",
                evidence=evidence_from_pairs(
                    安全组=rule.get("security_group_id"),
                    来源=source,
                    端口范围=rule.get("port_range"),
                    命中端口=",".join(str(port) for port in matched_ports),
                    协议=rule.get("ip_protocol"),
                ),
            )
        )
    return findings


def protocol_supports_port_range(ip_protocol: str) -> bool:
    text = str(ip_protocol or "").strip().lower()
    # 只对端口型协议做高危端口判定，避免把 ICMP 这类非端口协议误判为端口暴露。
    return text in {"", "tcp", "udp", "all", "sctp"}


def port_range_contains(port_range: str, target_port: int) -> bool:
    text = str(port_range or "").strip()
    if not text:
        return False
    if text in {"-1/-1", "1/65535", "0/65535"}:
        return True

    match = re.match(r"^(-?\d+)/(-?\d+)$", text)
    if not match:
        return False
    start = int(match.group(1))
    end = int(match.group(2))
    if start < 0 and end < 0:
        return True
    return start <= target_port <= end


def check_disks_without_snapshot_policy(context: CheckContext) -> list[CheckFinding]:
    check_id = "ecs_disk_without_snapshot_policy"
    if not context.config.is_enabled(check_id):
        return []

    failed_disk_ids = {
        row.get("resource_id", "")
        for row in context.details.collection_events
        if row.get("api") == "DescribeAutoSnapshotPolicyAssociations"
        and row.get("status") == "query_failed"
        and row.get("resource_id")
    }
    failed_regions = {
        row.get("region_id", "")
        for row in context.details.collection_events
        if row.get("api") == "DescribeAutoSnapshotPolicyAssociations"
        and row.get("status") == "query_failed"
        and not row.get("resource_id")
    }
    associated_disk_ids = {
        row.get("disk_id", "")
        for row in context.details.ecs_snapshot_policy_associations
        if row.get("disk_id")
    }
    findings = []
    for disk in context.details.ecs_disks:
        disk_id = disk.get("disk_id", "")
        if disk_id in failed_disk_ids or disk.get("region_id") in failed_regions:
            continue
        if not disk_id or disk_id in associated_disk_ids:
            continue
        findings.append(
            finding(
                disk,
                service="ecs（云服务器）",
                resource_type="云盘",
                severity="low",
                check_id=check_id,
                check_name="云盘未关联自动快照策略",
                category="未使用配置",
                message="云盘未发现自动快照策略关联。",
                recommendation="结合数据重要性确认是否需要自动快照；关键业务盘建议绑定合适的快照策略。",
                evidence=evidence_from_pairs(
                    状态=disk.get("status"),
                    容量GB=disk.get("size_gb"),
                    磁盘类型=disk.get("disk_type"),
                    挂载实例=disk.get("instance_id"),
                ),
            )
        )
    return findings
