"""RAM 身份与访问密钥巡检规则。"""

from __future__ import annotations

from .helpers import evidence_from_pairs, finding, masked_identifier
from .models import CheckContext, CheckFinding, parse_datetime


def run(context: CheckContext) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    findings.extend(check_root_access_keys(context))
    findings.extend(check_stale_access_keys(context))
    findings.extend(check_access_key_no_usage_record(context))
    findings.extend(check_access_key_rotation(context))
    findings.extend(check_inactive_access_key_cleanup(context))
    findings.extend(check_users_without_mfa(context))
    findings.extend(check_empty_groups(context))
    return findings


def _user_policy_summary(context: CheckContext, user_name: str) -> tuple[int, bool]:
    """返回 (策略数, 是否包含高危策略) 用于权限摘要。"""
    policy_names = {
        row.get("policy_name", "")
        for row in context.details.ram_user_policies
        if row.get("user_name") == user_name and row.get("policy_name")
    }
    has_high_privilege = bool(
        policy_names & context.config.high_privilege_policy_names
    )
    return len(policy_names), has_high_privilege


def _idle_days_str(days: int | None) -> str | int:
    """格式化闲置天数，避免 0 被当成 falsy 误显示为"未知"。"""
    if days is None:
        return "未知"
    return days


def check_root_access_keys(context: CheckContext) -> list[CheckFinding]:
    """Root 账号存在 Active AK 即报高危，不依赖闲置天数。"""
    check_id = "ram_root_access_key"
    if not context.config.is_enabled(check_id):
        return []

    findings = []
    for key in context.details.ram_root_access_keys:
        if key.get("last_used_query_failed") == "true":
            continue
        status = key.get("status", "").lower()
        if status and status != "active":
            continue
        last_used = parse_datetime(key.get("last_used_date", ""))
        created = parse_datetime(key.get("create_date", ""))
        reference = last_used or created
        idle_days = (context.now - reference).days if reference else None
        findings.append(
            finding(
                key,
                service="ram（访问控制）",
                resource_type="AccessKey",
                severity="high",
                check_id=check_id,
                check_name="Root 账号存在 AccessKey",
                category="高风险暴露",
                message="主账号（Root）存在 Active 状态 AccessKey，安全风险极高。",
                recommendation="Root 账号不应持有 AK；建议立即禁用，确认无依赖后删除，日常操作使用 RAM 子用户 + MFA。",
                evidence=evidence_from_pairs(
                    AccessKey=masked_identifier(key.get("access_key_id", "")),
                    状态=key.get("status"),
                    创建时间=key.get("create_date"),
                    最后使用时间=key.get("last_used_date") or "无记录",
                    闲置天数=_idle_days_str(idle_days),
                ),
            )
        )
    return findings


def check_stale_access_keys(context: CheckContext) -> list[CheckFinding]:
    """AK 分级闲置检查：仅对有 last_used_date 数据的 AK 做分级，
    无使用记录的 AK 由 check_access_key_no_usage_record 单独处理。"""
    check_id = "ram_stale_access_key"
    if not context.config.is_enabled(check_id):
        return []

    warn_days = context.config.stale_access_key_warn_days
    base_days = context.config.stale_access_key_days
    severe_days = context.config.stale_access_key_severe_days

    findings = []
    for key in context.details.ram_access_keys:
        if key.get("last_used_query_failed") == "true":
            continue
        status = key.get("status", "").lower()
        if status and status != "active":
            continue
        last_used = parse_datetime(key.get("last_used_date", ""))
        created = parse_datetime(key.get("create_date", ""))

        # 无 last_used_date 的 AK 不纳入本检查，交给 no_usage_record 单独处理
        if not last_used:
            continue

        idle_days = (context.now - last_used).days
        if idle_days < warn_days:
            continue

        # 分级严重度
        if idle_days >= severe_days:
            severity = "high"
        elif idle_days >= base_days:
            severity = "medium"
        else:
            severity = "low"

        # 权限叠加升级
        user_name = key.get("user_name", "")
        policy_count, has_high_privilege = _user_policy_summary(context, user_name)
        if has_high_privilege or policy_count >= context.config.high_privilege_policy_count:
            severity = "high"

        policy_desc = f"策略数={policy_count}"
        if has_high_privilege:
            matched = context.config.high_privilege_policy_names & {
                row.get("policy_name", "")
                for row in context.details.ram_user_policies
                if row.get("user_name") == user_name
            }
            policy_desc = f"含高危策略({','.join(sorted(matched))}), {policy_desc}"

        findings.append(
            finding(
                key,
                service="ram（访问控制）",
                resource_type="AccessKey",
                severity=severity,
                check_id=check_id,
                check_name="AK 分级闲置",
                category="未使用配置",
                message=f"RAM AccessKey 闲置 {idle_days} 天，超过阈值。",
                recommendation=(
                    "确认归属和调用链路；"
                    + ("高权限 AK 闲置风险极高，建议立即禁用；" if severity == "high" else "")
                    + ("不再使用的 AK 建议禁用后观察，再按流程删除。" if severity != "high" else "")
                ),
                evidence=evidence_from_pairs(
                    用户=user_name,
                    AccessKey=masked_identifier(key.get("access_key_id", "")),
                    最后使用时间=key.get("last_used_date"),
                    创建时间=key.get("create_date"),
                    闲置天数=idle_days,
                    权限摘要=policy_desc,
                ),
            )
        )
    return findings


def check_access_key_no_usage_record(context: CheckContext) -> list[CheckFinding]:
    """Active AK 无使用记录（last_used_date 为空）且创建时间超过阈值，
    无法确认是否仍在使用，需人工复核。"""
    check_id = "ram_access_key_no_usage_record"
    if not context.config.is_enabled(check_id):
        return []

    warn_days = context.config.stale_access_key_warn_days
    findings = []
    for key in context.details.ram_access_keys:
        if key.get("last_used_query_failed") == "true":
            continue
        status = key.get("status", "").lower()
        if status and status != "active":
            continue
        last_used = parse_datetime(key.get("last_used_date", ""))
        # 本检查只处理无使用记录的 AK
        if last_used:
            continue
        created = parse_datetime(key.get("create_date", ""))
        if not created:
            continue
        age_days = (context.now - created).days
        if age_days < warn_days:
            continue

        user_name = key.get("user_name", "")
        policy_count, has_high_privilege = _user_policy_summary(context, user_name)
        severity = "low"
        if has_high_privilege or policy_count >= context.config.high_privilege_policy_count:
            severity = "medium"

        findings.append(
            finding(
                key,
                service="ram（访问控制）",
                resource_type="AccessKey",
                severity=severity,
                check_id=check_id,
                check_name="AK 无法确认使用状态",
                category="未使用配置",
                message="AccessKey 无使用记录（GetAccessKeyLastUsed 未返回数据），无法确认是否仍在使用，需人工复核。",
                recommendation="确认该 AK 的归属和调用链路；如确认仍在使用则标记白名单；如不再使用建议禁用后观察再删除。",
                evidence=evidence_from_pairs(
                    用户=user_name,
                    AccessKey=masked_identifier(key.get("access_key_id", "")),
                    创建时间=key.get("create_date"),
                    创建距今天数=age_days,
                    权限摘要=f"策略数={policy_count}" + (f", 含高危策略" if has_high_privilege else ""),
                ),
            )
        )
    return findings


def check_access_key_rotation(context: CheckContext) -> list[CheckFinding]:
    """Active AK 创建超过轮转阈值天数，提示轮转。"""
    check_id = "ram_access_key_rotation"
    if not context.config.is_enabled(check_id):
        return []

    rotation_days = context.config.access_key_rotation_days
    findings = []
    for key in context.details.ram_access_keys:
        if key.get("last_used_query_failed") == "true":
            continue
        status = key.get("status", "").lower()
        if status and status != "active":
            continue
        created = parse_datetime(key.get("create_date", ""))
        if not created:
            continue
        age_days = (context.now - created).days
        if age_days < rotation_days:
            continue
        findings.append(
            finding(
                key,
                service="ram（访问控制）",
                resource_type="AccessKey",
                severity="medium",
                check_id=check_id,
                check_name="AK 长期未轮转",
                category="身份安全",
                message=f"AccessKey 创建已超过 {rotation_days} 天未轮转。",
                recommendation="建议创建新 AK -> 替换应用配置 -> 禁用旧 AK -> 观察无调用后删除旧 AK。",
                evidence=evidence_from_pairs(
                    用户=key.get("user_name"),
                    AccessKey=masked_identifier(key.get("access_key_id", "")),
                    创建时间=key.get("create_date"),
                    服役天数=age_days,
                    最后使用时间=key.get("last_used_date") or "无记录",
                    轮转阈值天数=rotation_days,
                ),
            )
        )
    return findings


def check_inactive_access_key_cleanup(context: CheckContext) -> list[CheckFinding]:
    """Inactive AK 残留超过阈值天数，提示删除。"""
    check_id = "ram_inactive_access_key_cleanup"
    if not context.config.is_enabled(check_id):
        return []

    cleanup_days = context.config.inactive_access_key_cleanup_days
    findings = []
    for key in context.details.ram_access_keys:
        status = key.get("status", "").lower()
        if status != "inactive":
            continue
        last_used = parse_datetime(key.get("last_used_date", ""))
        created = parse_datetime(key.get("create_date", ""))
        reference = last_used or created
        if not reference:
            continue
        inactive_days = (context.now - reference).days
        if inactive_days < cleanup_days:
            continue
        findings.append(
            finding(
                key,
                service="ram（访问控制）",
                resource_type="AccessKey",
                severity="low",
                check_id=check_id,
                check_name="Inactive AK 长期残留",
                category="未使用配置",
                message=f"AccessKey 已禁用超过 {cleanup_days} 天，建议删除。",
                recommendation="确认无依赖后删除；Inactive AK 虽不可调用但 AK 前缀仍在系统中，存在泄露风险。",
                evidence=evidence_from_pairs(
                    用户=key.get("user_name"),
                    AccessKey=masked_identifier(key.get("access_key_id", "")),
                    状态=key.get("status"),
                    创建时间=key.get("create_date"),
                    最后使用时间=key.get("last_used_date") or "无记录",
                    禁用天数=inactive_days,
                    清理阈值天数=cleanup_days,
                ),
            )
        )
    # Root Inactive AK 同样提示
    for key in context.details.ram_root_access_keys:
        status = key.get("status", "").lower()
        if status != "inactive":
            continue
        last_used = parse_datetime(key.get("last_used_date", ""))
        created = parse_datetime(key.get("create_date", ""))
        reference = last_used or created
        if not reference:
            continue
        inactive_days = (context.now - reference).days
        if inactive_days < cleanup_days:
            continue
        findings.append(
            finding(
                key,
                service="ram（访问控制）",
                resource_type="AccessKey",
                severity="low",
                check_id=check_id,
                check_name="Inactive AK 长期残留",
                category="未使用配置",
                message=f"Root 账号 AccessKey 已禁用超过 {cleanup_days} 天，建议删除。",
                recommendation="Root 账号 Inactive AK 应尽早删除，彻底消除泄露风险。",
                evidence=evidence_from_pairs(
                    AccessKey=masked_identifier(key.get("access_key_id", "")),
                    状态=key.get("status"),
                    创建时间=key.get("create_date"),
                    最后使用时间=key.get("last_used_date") or "无记录",
                    禁用天数=inactive_days,
                    清理阈值天数=cleanup_days,
                ),
            )
        )
    return findings


def check_users_without_mfa(context: CheckContext) -> list[CheckFinding]:
    check_id = "ram_user_without_mfa"
    if not context.config.is_enabled(check_id):
        return []

    # MFA 查询失败的用户无法判断 MFA 状态，跳过以避免误判
    mfa_query_failed = {
        row.get("user_name", "")
        for row in context.details.ram_user_mfa
        if row.get("user_name") and row.get("mfa_query_failed") == "true"
    }
    mfa_users = {
        row.get("user_name", "")
        for row in context.details.ram_user_mfa
        if row.get("user_name") and row.get("mfa_enabled") == "true"
        and row.get("mfa_query_failed") != "true"
    }
    findings = []
    for user in context.details.ram_users:
        user_name = user.get("user_name", "")
        if not user_name or user_name in mfa_users or user_name in mfa_query_failed:
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
