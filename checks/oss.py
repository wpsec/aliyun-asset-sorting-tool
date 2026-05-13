"""OSS Bucket 元数据巡检规则。"""

from __future__ import annotations

from .helpers import evidence_from_pairs, finding
from .models import CheckContext, CheckFinding


def run(context: CheckContext) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    findings.extend(check_bucket_without_encryption(context))
    findings.extend(check_bucket_public_access(context))
    findings.extend(check_bucket_without_lifecycle(context))
    return findings


def check_bucket_without_encryption(context: CheckContext) -> list[CheckFinding]:
    check_id = "oss_bucket_without_encryption"
    if not context.config.is_enabled(check_id):
        return []

    findings = []
    for bucket in context.details.oss_buckets:
        if bucket.get("encryption_algorithm"):
            continue
        findings.append(
            finding(
                bucket,
                service="oss（对象存储）",
                resource_type="OSS Bucket",
                severity="medium",
                check_id=check_id,
                check_name="Bucket 未开启服务端加密",
                category="未使用配置",
                message="Bucket 元数据未发现服务端加密配置。",
                recommendation="根据数据分级启用 OSS 服务端加密；涉及敏感数据时优先使用 KMS 托管密钥。",
                evidence=evidence_from_pairs(Bucket=bucket.get("bucket_name"), 地域=bucket.get("region_id"), ACL=bucket.get("acl")),
            )
        )
    return findings


def check_bucket_without_lifecycle(context: CheckContext) -> list[CheckFinding]:
    check_id = "oss_bucket_without_lifecycle"
    if not context.config.is_enabled(check_id):
        return []

    findings = []
    for bucket in context.details.oss_buckets:
        if bucket.get("lifecycle_query_failed") == "true":
            continue
        if bucket.get("lifecycle_configured") == "true":
            continue
        findings.append(
            finding(
                bucket,
                service="oss（对象存储）",
                resource_type="OSS Bucket",
                severity="low",
                check_id=check_id,
                check_name="Bucket 未配置生命周期",
                category="未使用配置",
                message="Bucket 未发现生命周期规则。",
                recommendation="结合数据保留周期配置生命周期规则，减少长期保留无效对象带来的存储成本。",
                evidence=evidence_from_pairs(
                    Bucket=bucket.get("bucket_name"),
                    地域=bucket.get("region_id"),
                    ACL=bucket.get("acl"),
                ),
            )
        )
    return findings


def check_bucket_public_access(context: CheckContext) -> list[CheckFinding]:
    check_id = "oss_bucket_public_access"
    if not context.config.is_enabled(check_id):
        return []

    findings = []
    for bucket in context.details.oss_buckets:
        acl = bucket.get("acl", "").lower()
        policy_public = bucket.get("policy_public", "").lower() == "true"
        pab_enabled = bucket.get("public_access_block", "").lower() == "true"
        if acl not in {"public-read", "public-read-write"} and not policy_public:
            continue
        severity = "high" if not pab_enabled else "medium"
        findings.append(
            finding(
                bucket,
                service="oss（对象存储）",
                resource_type="OSS Bucket",
                severity=severity,
                check_id=check_id,
                check_name="Bucket 存在公开访问风险",
                category="高风险暴露",
                message="Bucket ACL 或 Bucket Policy 存在公开访问风险。",
                recommendation="确认公开访问是否为业务必要；非必要场景建议改为私有读写，并开启阻止公共访问。",
                evidence=evidence_from_pairs(
                    Bucket=bucket.get("bucket_name"),
                    ACL=bucket.get("acl"),
                    Policy公开=bucket.get("policy_public"),
                    阻止公共访问=bucket.get("public_access_block"),
                ),
            )
        )
    return findings
