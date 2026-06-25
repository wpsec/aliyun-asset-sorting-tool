"""巡检数据模型和规则配置。"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
SEVERITY_NAMES = {"low": "低", "medium": "中", "high": "高"}
BILLABLE_IDLE_RESOURCE_TYPES = {
    "云服务器",
    "云盘",
    "弹性公网IP",
    "NAT网关",
    "VPN网关",
    "负载均衡",
    "RDS实例",
    "Redis/Tair实例",
}
NON_BILLABLE_RESOURCE_TYPES = {
    "专有网络",
    "交换机",
    "安全组",
    "安全组规则",
    "RAM用户",
    "RAM用户组",
    "AccessKey",
    "服务器组",
}
USAGE_BILLED_RESOURCE_TYPES = {
    "OSS Bucket",
    "SLS Project",
    "SLS Logstore",
}

CHECK_ID_ALIASES = {
    "未挂载云盘": "ecs_unused_disk",
    "已停止ECS实例": "ecs_stopped_instance",
    "已停止 ECS 实例": "ecs_stopped_instance",
    "安全组未绑定实例": "ecs_unused_security_group",
    "安全组高危端口公网开放": "ecs_high_risk_security_group_rule",
    "空VPC": "vpc_empty_vpc",
    "空交换机": "vpc_empty_vswitch",
    "未绑定EIP": "vpc_unused_eip",
    "NAT网关无SNAT或DNAT规则": "vpc_nat_without_rules",
    "VPN网关无连接": "vpc_vpn_without_connection",
    "VPN网关无IPsec或SSL配置": "vpc_vpn_without_connection",
    "负载均衡无监听": "slb_without_listener",
    "服务器组无后端服务器": "slb_server_group_without_backend",
    "长期未使用AK": "ram_stale_access_key",
    "AK无法确认使用状态": "ram_access_key_no_usage_record",
    "Root账号存在AccessKey": "ram_root_access_key",
    "AK长期未轮转": "ram_access_key_rotation",
    "Inactive AK长期残留": "ram_inactive_access_key_cleanup",
    "RAM用户未启用MFA": "ram_user_without_mfa",
    "空RAM用户组": "ram_empty_group",
    "OSS Bucket未开启服务端加密": "oss_bucket_without_encryption",
    "OSS Bucket公开访问风险": "oss_bucket_public_access",
    "云盘未关联自动快照策略": "ecs_disk_without_snapshot_policy",
    "RDS存在公网连接地址": "rds_public_endpoint",
    "Redis存在公网连接地址": "redis_public_endpoint",
    "OSS Bucket未配置生命周期": "oss_bucket_without_lifecycle",
    "公网负载均衡未发现HTTPS或TLS监听": "slb_public_without_https",
    "公网负载均衡未发现 HTTPS/TLS 监听": "slb_public_without_https",
    "ECS低使用率疑似闲置": "metric_idle_ecs",
    "EIP低流量疑似闲置": "metric_idle_eip",
    "SLB低QPS疑似闲置": "metric_idle_slb",
    "RDS低连接数疑似闲置": "metric_idle_rds",
    "Redis低QPS疑似闲置": "metric_idle_redis",
}

METRIC_THRESHOLD_ALIASES = {
    "ECS平均CPU百分比": "ecs_cpu_avg_percent",
    "ECS公网出方向平均Bps": "ecs_network_out_avg_bps",
    "EIP平均流量Bps": "eip_traffic_avg_bps",
    "SLB平均QPS": "slb_qps_avg",
    "RDS平均连接数": "rds_connection_avg",
    "Redis平均QPS": "redis_qps_avg",
}


@dataclasses.dataclass(frozen=True)
class CheckFinding:
    subscription: str
    account_id: str
    region_id: str
    service: str
    resource_type: str
    resource_id: str
    resource_name: str
    severity: str
    check_id: str
    check_name: str
    category: str
    finding: str
    recommendation: str
    evidence: str
    tags: str = ""
    resource_group_id: str = ""

    def to_row(self) -> dict[str, str]:
        return {
            "subscription": self.subscription,
            "account_id": self.account_id,
            "region_id": self.region_id,
            "service": self.service,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "severity": SEVERITY_NAMES.get(self.severity, self.severity),
            "severity_code": self.severity,
            "remediation_priority": remediation_priority(self),
            "billing_attribute": billing_attribute(self),
            "billing_note": billing_note(self),
            "check_id": self.check_id,
            "check_name": self.check_name,
            "category": self.category,
            "finding": self.finding,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


@dataclasses.dataclass(frozen=True)
class ChecksConfig:
    enabled: dict[str, bool]
    high_risk_ports: set[int]
    stale_access_key_days: int
    stale_access_key_warn_days: int
    stale_access_key_severe_days: int
    access_key_rotation_days: int
    inactive_access_key_cleanup_days: int
    high_privilege_policy_names: set[str]
    high_privilege_policy_count: int
    whitelist_resource_ids: set[str]
    whitelist_resource_group_ids: set[str]
    whitelist_tags: dict[str, set[str]]
    metric_checks_enabled: bool
    metric_windows_days: list[int]
    metric_period_seconds: int
    metric_thresholds: dict[str, float]
    severity_threshold: str = "low"

    @classmethod
    def default(cls) -> "ChecksConfig":
        return cls(
            enabled={
                "ecs_unused_disk": True,
                "ecs_stopped_instance": True,
                "ecs_unused_security_group": True,
                "ecs_high_risk_security_group_rule": True,
                "vpc_empty_vpc": True,
                "vpc_empty_vswitch": True,
                "vpc_unused_eip": True,
                "vpc_nat_without_rules": True,
                "vpc_vpn_without_connection": True,
                "slb_without_listener": True,
                "slb_server_group_without_backend": True,
                "ram_stale_access_key": True,
                "ram_access_key_no_usage_record": True,
                "ram_root_access_key": True,
                "ram_access_key_rotation": True,
                "ram_inactive_access_key_cleanup": True,
                "ram_user_without_mfa": True,
                "ram_empty_group": True,
                "oss_bucket_without_encryption": True,
                "oss_bucket_public_access": True,
                "ecs_disk_without_snapshot_policy": True,
                "rds_public_endpoint": True,
                "redis_public_endpoint": True,
                "oss_bucket_without_lifecycle": True,
                "slb_public_without_https": True,
                "metric_idle_ecs": True,
                "metric_idle_eip": True,
                "metric_idle_slb": True,
                "metric_idle_rds": True,
                "metric_idle_redis": True,
            },
            high_risk_ports={22, 3389, 3306, 5432, 6379, 9200, 9300, 27017},
            stale_access_key_days=90,
            stale_access_key_warn_days=30,
            stale_access_key_severe_days=180,
            access_key_rotation_days=365,
            inactive_access_key_cleanup_days=90,
            high_privilege_policy_names={"AdministratorAccess"},
            high_privilege_policy_count=10,
            whitelist_resource_ids=set(),
            whitelist_resource_group_ids=set(),
            whitelist_tags={},
            metric_checks_enabled=False,
            metric_windows_days=[7, 14, 30],
            metric_period_seconds=3600,
            metric_thresholds={
                "ecs_cpu_avg_percent": 3.0,
                "ecs_network_out_avg_bps": 1024.0,
                "eip_traffic_avg_bps": 1024.0,
                "slb_qps_avg": 0.1,
                "rds_connection_avg": 1.0,
                "redis_qps_avg": 0.1,
            },
        )

    @classmethod
    def from_file(cls, path: str | Path, threshold: str) -> "ChecksConfig":
        config = cls.default()
        if not path:
            return dataclasses.replace(config, severity_threshold=threshold)

        with Path(path).open("r", encoding="utf-8") as fp:
            data = json.load(fp)

        enabled = dict(config.enabled)
        enabled.update(
            normalize_enabled_checks(config_section(data, "enabled_checks", "启用巡检项"))
        )
        ports = config_value(
            data,
            "high_risk_ports",
            "高危端口",
            default=sorted(config.high_risk_ports),
        )
        stale_days = int(
            config_value(
                data,
                "stale_access_key_days",
                "访问密钥未使用天数阈值",
                "AK未使用天数阈值",
                default=config.stale_access_key_days,
            )
        )
        stale_warn_days = int(
            config_value(
                data,
                "stale_access_key_warn_days",
                "AK闲置低风险天数阈值",
                default=config.stale_access_key_warn_days,
            )
        )
        stale_severe_days = int(
            config_value(
                data,
                "stale_access_key_severe_days",
                "AK闲置高风险天数阈值",
                default=config.stale_access_key_severe_days,
            )
        )
        rotation_days = int(
            config_value(
                data,
                "access_key_rotation_days",
                "AK轮转天数阈值",
                default=config.access_key_rotation_days,
            )
        )
        inactive_cleanup_days = int(
            config_value(
                data,
                "inactive_access_key_cleanup_days",
                "Inactive AK清理天数阈值",
                default=config.inactive_access_key_cleanup_days,
            )
        )
        high_privilege_names = set(
            config_value(
                data,
                "high_privilege_policy_names",
                "高危策略名",
                default=sorted(config.high_privilege_policy_names),
            )
        )
        high_privilege_count = int(
            config_value(
                data,
                "high_privilege_policy_count",
                "高危策略数量阈值",
                default=config.high_privilege_policy_count,
            )
        )
        whitelist = config_section(data, "whitelist", "白名单")
        whitelist_tags = normalize_whitelist_tags(whitelist.get("tags", []))
        if not whitelist_tags:
            whitelist_tags = normalize_whitelist_tags(whitelist.get("标签", []))
        metric_settings = config_section(data, "metric_checks", "指标巡检")
        metric_thresholds = dict(config.metric_thresholds)
        metric_thresholds.update(
            normalize_metric_thresholds(config_section(metric_settings, "thresholds", "阈值"))
        )
        return cls(
            enabled=enabled,
            high_risk_ports={int(port) for port in ports},
            stale_access_key_days=stale_days,
            stale_access_key_warn_days=stale_warn_days,
            stale_access_key_severe_days=stale_severe_days,
            access_key_rotation_days=rotation_days,
            inactive_access_key_cleanup_days=inactive_cleanup_days,
            high_privilege_policy_names=high_privilege_names,
            high_privilege_policy_count=high_privilege_count,
            whitelist_resource_ids={
                str(item)
                for item in config_value(
                    whitelist,
                    "resource_ids",
                    "资源ID",
                    "资源ID列表",
                    default=[],
                )
                if str(item)
            },
            whitelist_resource_group_ids={
                str(item)
                for item in config_value(
                    whitelist,
                    "resource_group_ids",
                    "资源组ID",
                    "资源组ID列表",
                    default=[],
                )
                if str(item)
            },
            whitelist_tags=whitelist_tags,
            metric_checks_enabled=parse_bool(
                config_value(
                    metric_settings,
                    "enabled",
                    "启用",
                    default=config.metric_checks_enabled,
                ),
                config.metric_checks_enabled,
            ),
            metric_windows_days=[
                int(item)
                for item in config_value(
                    metric_settings,
                    "windows_days",
                    "统计窗口天数",
                    default=config.metric_windows_days,
                )
            ],
            metric_period_seconds=int(
                config_value(
                    metric_settings,
                    "period_seconds",
                    "采样周期秒",
                    default=config.metric_period_seconds,
                )
            ),
            metric_thresholds=metric_thresholds,
            severity_threshold=threshold,
        )

    def is_enabled(self, check_id: str) -> bool:
        return self.enabled.get(check_id, True)

    def allows_severity(self, severity: str) -> bool:
        min_level = SEVERITY_ORDER.get(self.severity_threshold, 1)
        return SEVERITY_ORDER.get(severity, 1) >= min_level

    def is_whitelisted(self, finding: CheckFinding) -> bool:
        if finding.resource_id in self.whitelist_resource_ids:
            return True
        if finding.resource_group_id in self.whitelist_resource_group_ids:
            return True
        tags = parse_tag_string(finding.tags)
        for key, allowed_values in self.whitelist_tags.items():
            value = tags.get(key)
            if value is None:
                continue
            if "*" in allowed_values or value in allowed_values:
                return True
        return False


@dataclasses.dataclass(frozen=True)
class CheckContext:
    raw_rows: list[dict[str, str]]
    details: Any
    config: ChecksConfig
    now: dt.datetime


def parse_datetime(value: str) -> dt.datetime | None:
    if not value:
        return None
    text = str(value).strip()
    for suffix in ("Z", "+0000"):
        if text.endswith(suffix):
            text = text[: -len(suffix)] + "+00:00"
            break
    formats = (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    )
    for fmt in formats:
        try:
            parsed = dt.datetime.strptime(text, fmt)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=dt.timezone.utc)
            return parsed.astimezone(dt.timezone.utc)
        except ValueError:
            continue
    return None


def parse_tag_string(value: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for item in str(value or "").split(";"):
        if "=" not in item:
            continue
        key, val = item.split("=", 1)
        key = key.strip()
        if key:
            tags[key] = val.strip()
    return tags


def normalize_whitelist_tags(value: Any) -> dict[str, set[str]]:
    tags: dict[str, set[str]] = {}
    if isinstance(value, dict):
        for key, val in value.items():
            if str(key).startswith("_"):
                continue
            if isinstance(val, list):
                tags[str(key)] = {str(item) for item in val}
            else:
                tags[str(key)] = {str(val)}
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                key = str(
                    item.get("key")
                    or item.get("Key")
                    or item.get("键")
                    or item.get("标签键")
                    or ""
                )
                val = str(
                    item.get("value")
                    or item.get("Value")
                    or item.get("值")
                    or item.get("标签值")
                    or "*"
                )
                if key:
                    tags.setdefault(key, set()).add(val)
    return tags


def config_value(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in data:
            return data[key]
    return default


def config_section(data: dict[str, Any], *keys: str) -> dict[str, Any]:
    value = config_value(data, *keys, default={})
    if isinstance(value, dict):
        return value
    return {}


def parse_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "y", "on", "是", "启用", "开启"}:
        return True
    if text in {"false", "0", "no", "n", "off", "否", "禁用", "关闭"}:
        return False
    return default


def normalize_enabled_checks(value: dict[str, Any]) -> dict[str, bool]:
    enabled: dict[str, bool] = {}
    for key, item in value.items():
        text = str(key)
        if text.startswith("_"):
            continue
        check_id = CHECK_ID_ALIASES.get(text, text)
        enabled[check_id] = parse_bool(item, True)
    return enabled


def normalize_metric_thresholds(value: dict[str, Any]) -> dict[str, float]:
    thresholds: dict[str, float] = {}
    for key, item in value.items():
        text = str(key)
        if text.startswith("_"):
            continue
        threshold_id = METRIC_THRESHOLD_ALIASES.get(text, text)
        thresholds[threshold_id] = float(item)
    return thresholds


def remediation_priority(finding: CheckFinding) -> str:
    if finding.severity == "high" and finding.category == "高风险暴露":
        return "P0-高危暴露"
    if finding.category == "疑似闲置":
        return "P1-闲置计费资源"
    if (
        finding.category == "闲置资源"
        and finding.resource_type in BILLABLE_IDLE_RESOURCE_TYPES
    ):
        return "P1-闲置计费资源"
    if finding.service.startswith("ram") or finding.resource_type in {"AccessKey", "RAM用户"}:
        return "P2-身份风险"
    if finding.severity == "medium":
        return "P2-中风险配置"
    return "P3-一般优化"


def billing_attribute(finding: CheckFinding) -> str:
    if finding.category == "疑似闲置":
        return "疑似持续计费"
    if finding.resource_type in BILLABLE_IDLE_RESOURCE_TYPES:
        return "持续计费"
    if finding.resource_type in USAGE_BILLED_RESOURCE_TYPES:
        return "用量计费"
    if finding.resource_type in NON_BILLABLE_RESOURCE_TYPES:
        return "通常不直接计费"
    if "oss（" in finding.service.lower() or "log（" in finding.service.lower():
        return "用量计费"
    if "ram（" in finding.service.lower() or finding.service.startswith("ram"):
        return "通常不直接计费"
    return "需账单确认"


def billing_note(finding: CheckFinding) -> str:
    if finding.resource_type == "云服务器":
        return "ECS 实例规格、公网带宽、镜像和系统盘等可能持续计费；停机不一定停止全部费用。"
    if finding.resource_type == "云盘":
        return "云盘按容量和时长计费，未挂载也会产生费用。"
    if finding.resource_type == "弹性公网IP":
        return "EIP 可能产生公网网络费、带宽费或公网 IP 保有费。"
    if finding.resource_type == "NAT网关":
        return "NAT 网关通常包含实例费和 CU 费，关联 EIP 另行计费。"
    if finding.resource_type == "VPN网关":
        return "VPN 网关按实例功能、带宽、SSL 规格等计费，预付费到期前仍占用成本。"
    if finding.resource_type == "负载均衡":
        return "负载均衡实例可能产生实例费、LCU/容量费、公网网络费等。"
    if finding.resource_type in {"RDS实例", "Redis/Tair实例"}:
        return "数据库实例通常按规格、存储、备份或 Serverless 用量计费。"
    if finding.resource_type == "OSS Bucket":
        return "Bucket 本身不是主要成本，费用来自对象存储容量、请求、流量和增值功能。"
    if finding.resource_type in {"SLS Project", "SLS Logstore"}:
        return "SLS 费用来自写入、存储、索引、Shard、读写请求、加工和投递等用量。"
    if finding.resource_type in {"专有网络", "交换机"}:
        return "VPC 和交换机通常不直接计费，但其中承载的 ECS、数据库、负载均衡、NAT、VPN 等资源会计费。"
    if finding.resource_type in {"安全组", "安全组规则"}:
        return "安全组通常不直接计费，主要是安全暴露或配置治理问题。"
    if finding.resource_type in {"RAM用户", "RAM用户组", "AccessKey"}:
        return "RAM 通常不直接计费，主要是身份安全和权限治理问题。"
    if finding.resource_type == "服务器组":
        return "服务器组通常是负载均衡配置对象，成本主要来自负载均衡实例本身。"
    if finding.category == "疑似闲置":
        return "该项基于云监控指标判断低使用率，是否可降配或释放需结合业务确认。"
    return "无法仅凭资产元数据确认费用，请以费用与成本账单明细为准。"
