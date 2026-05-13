"""RAM 身份与访问密钥巡检规则。"""

from __future__ import annotations

from .helpers import evidence_from_pairs, finding, masked_identifier
from .models import CheckContext, CheckFinding, parse_datetime


def run(context: CheckContext) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    findings.extend(check_stale_access_keys(context))
    findings.extend(check_users_without_mfa(context))
    findings.extend(check_empty_groups(context))
    return findings


def check_stale_access_keys(context: CheckContext) -> list[CheckFinding]:
    check_id = "ram_stale_access_key"
    if not context.config.is_enabled(check_id):
        return []

    findings = []
    for key in context.details.ram_access_keys:
        if key.get("last_used_query_failed") == "true":
            continue
        status = key.get("status", "").lower()
        if status and status != "active":
            continue
        last_used = parse_datetime(key.get("last_used_date", ""))
        created = parse_datetime(key.get("create_date", ""))
        reference = last_used or created
        if not reference:
            continue
        age_days = (context.now - reference).days
        if age_days < context.config.stale_access_key_days:
            continue
        finding_text = "RAM AccessKey 长期未使用。"
        if not last_used:
            finding_text = "RAM AccessKey 未发现使用记录，且创建时间已超过阈值。"
        findings.append(
            finding(
                key,
                service="ram（访问控制）",
                resource_type="AccessKey",
                severity="medium",
                check_id=check_id,
                check_name="AK 超过阈值未使用",
                category="未使用配置",
                message=finding_text,
                recommendation="确认归属和调用链路；不再使用的 AK 建议禁用后观察，再按流程删除。",
                evidence=evidence_from_pairs(
                    用户=key.get("user_name"),
                    AccessKey=masked_identifier(key.get("access_key_id", "")),
                    最后使用时间=key.get("last_used_date") or "无记录",
                    创建时间=key.get("create_date"),
                    阈值天数=context.config.stale_access_key_days,
                    已闲置天数=age_days,
                ),
            )
        )
    return findings


def check_users_without_mfa(context: CheckContext) -> list[CheckFinding]:
    check_id = "ram_user_without_mfa"
    if not context.config.is_enabled(check_id):
        return []

    mfa_users = {
        row.get("user_name", "")
        for row in context.details.ram_user_mfa
        if row.get("user_name") and row.get("mfa_enabled") == "true"
    }
    findings = []
    for user in context.details.ram_users:
        user_name = user.get("user_name", "")
        if not user_name or user_name in mfa_users:
            continue
        findings.append(
            finding(
                user,
                service="ram（访问控制）",
                resource_type="RAM用户",
                severity="medium",
                check_id=check_id,
                check_name="RAM 用户未启用 MFA",
                category="未使用配置",
                message="RAM 用户未发现 MFA 绑定信息。",
                recommendation="对可登录控制台或高权限用户启用 MFA；无登录需求的用户建议关闭控制台登录。",
                evidence=evidence_from_pairs(用户=user_name, 创建时间=user.get("create_date")),
            )
        )
    return findings


def check_empty_groups(context: CheckContext) -> list[CheckFinding]:
    check_id = "ram_empty_group"
    if not context.config.is_enabled(check_id):
        return []

    groups_with_users = {
        row.get("group_name", "")
        for row in context.details.ram_group_users
        if row.get("group_name") and row.get("user_name")
    }
    findings = []
    for group in context.details.ram_groups:
        group_name = group.get("group_name", "")
        if not group_name or group_name in groups_with_users:
            continue
        findings.append(
            finding(
                group,
                service="ram（访问控制）",
                resource_type="RAM用户组",
                severity="low",
                check_id=check_id,
                check_name="空用户组",
                category="未使用配置",
                message="RAM 用户组内未发现用户。",
                recommendation="确认是否仍作为权限模板保留；不再使用的空用户组建议清理。",
                evidence=evidence_from_pairs(用户组=group_name, 创建时间=group.get("create_date")),
            )
        )
    return findings
